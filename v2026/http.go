package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// a simple http/https proxy focused on proper file descriptor management

// discardLog swallows net/http's per-connection error logging. Connections and
// packet flow driven by a client must never log on the server: the client picks
// the rate, and the server pays. See `SocksStats` for the same reasoning on the
// socks path.
var discardLog = log.New(io.Discard, "", 0)

// minProxyConnectTimeout floors the dial backoff. `connect.NewReconnect(0)`
// yields an already-closed channel, so a zero ProxyConnectTimeout (the struct's
// zero value, and `NewHttpProxy`'s default) would turn the dial retry into a hot
// spin that pegs a core.
const minProxyConnectTimeout = 1 * time.Second

// maxEarlyClientBytes bounds what a client may send ahead of an established
// tunnel before the close-watch stops buffering. A client that opportunistically
// pipelines its TLS ClientHello with the CONNECT sends a few hundred bytes and
// then waits for the tunnel.
const maxEarlyClientBytes = 64 * 1024

// HttpProxySettings configures an HttpProxy. Take DefaultHttpProxySettings and
// adjust it; nothing is left to a zero value meaning "default".
type HttpProxySettings struct {
	// ProxyReadTimeout bounds each read on the data path. A tunnel idle for
	// longer is torn down — intentionally: a WAN connection with no heartbeat is
	// going to be dropped by the network anyway.
	ProxyReadTimeout time.Duration
	// ProxyWriteTimeout bounds each write.
	ProxyWriteTimeout time.Duration
	// ProxyIdleTimeout is the http server's keep-alive idle timeout.
	ProxyIdleTimeout time.Duration
	// ProxyConnectTimeout is the backoff between upstream dial attempts. The dial
	// retries until the client drops, so this paces the retries; it does not bound
	// them. It is floored at minProxyConnectTimeout.
	ProxyConnectTimeout time.Duration
	// ProxyTlsHandshakeTimeout applies to the plain-http proxy path only.
	ProxyTlsHandshakeTimeout time.Duration
	// MaxHttpBodyBytes caps the request body the plain-http path will buffer.
	MaxHttpBodyBytes int64

	// Log receives the periodic stats flush and panics. The data path itself never
	// logs. nil resolves to `connect.DefaultLogger()`.
	Log connect.Logger
	// StatsLogInterval is how often the data path's counters are flushed to the
	// log (only when they have changed). Zero disables the flush.
	StatsLogInterval time.Duration
}

func DefaultHttpProxySettings() *HttpProxySettings {
	return &HttpProxySettings{
		ProxyReadTimeout:         30 * time.Second,
		ProxyWriteTimeout:        15 * time.Second,
		ProxyIdleTimeout:         5 * time.Minute,
		ProxyConnectTimeout:      30 * time.Minute,
		ProxyTlsHandshakeTimeout: 30 * time.Second,
		MaxHttpBodyBytes:         2 * 1024 * 1024,
		StatsLogInterval:         DefaultStatsLogInterval,
	}
}

type HttpProxy struct {
	settings *HttpProxySettings
	stats    HttpStats

	ConnectDialWithRequest func(r *http.Request, network string, addr string) (net.Conn, error)
	GetTlsConfigForClient  func(*tls.ClientHelloInfo) (*tls.Config, error)
}

func NewHttpProxy(settings *HttpProxySettings) *HttpProxy {
	return &HttpProxy{
		settings: settings,
	}
}

func NewHttpProxyWithDefaults() *HttpProxy {
	return NewHttpProxy(DefaultHttpProxySettings())
}

func (self *HttpProxy) Settings() *HttpProxySettings {
	return self.settings
}

// Stats returns the http data path's counters. Nothing on that path logs — a
// client picks the rate, so logging would let it drive unbounded server I/O — so
// these are how dial failures, aborts and dropped clients are observed. They are
// also flushed to the log on StatsLogInterval.
func (self *HttpProxy) Stats() HttpStatsSnapshot {
	return self.stats.Snapshot()
}

func (self *HttpProxy) logger() connect.Logger {
	if self.settings.Log != nil {
		return self.settings.Log
	}
	return connect.DefaultLogger()
}

func (self *HttpProxy) proxyConnectTimeout() time.Duration {
	if self.settings.ProxyConnectTimeout < minProxyConnectTimeout {
		return minProxyConnectTimeout
	}
	return self.settings.ProxyConnectTimeout
}

func (self *HttpProxy) ListenAndServe(ctx context.Context, network string, addr string) error {

	listenConfig := net.ListenConfig{}

	l, err := listenConfig.Listen(
		ctx,
		network,
		addr,
	)
	if err != nil {
		return err
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      self,
		ReadTimeout:  self.settings.ProxyReadTimeout,
		WriteTimeout: self.settings.ProxyWriteTimeout,
		IdleTimeout:  self.settings.ProxyIdleTimeout,
		// net/http logs client-driven failures here — a bad TLS handshake, a
		// malformed request, a connection that hung up. A client controls how often
		// those happen, so leaving this at the default hands it a log-amplification
		// vector: one malformed byte buys a disk write. Discard them.
		ErrorLog: discardLog,
		// Every request context descends from runCtx, so shutting the proxy down
		// tears down in-flight handlers. This is the ONLY thing that reaches a
		// hijacked tunnel: `Server.Close` deliberately knows nothing about hijacked
		// connections, so without this a CONNECT relay to a black-holed upstream
		// would outlive the server and hold its fds until the process exits.
		BaseContext: func(net.Listener) context.Context {
			return runCtx
		},
	}

	go connect.HandleError(func() {
		defer l.Close()
		defer httpServer.Close()
		select {
		case <-runCtx.Done():
		}
	})

	go connect.HandleError(func() {
		logStatsPeriodically(runCtx, self.logger(), "[http]", self.settings.StatsLogInterval, self.Stats)
	})

	return httpServer.Serve(l)
}

func (self *HttpProxy) ListenAndServeTls(ctx context.Context, network string, addr string) error {

	tlsConfig := &tls.Config{
		GetConfigForClient: self.GetTlsConfigForClient,
	}

	listenConfig := net.ListenConfig{}

	l, err := listenConfig.Listen(
		ctx,
		network,
		addr,
	)
	if err != nil {
		return err
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      self,
		TLSConfig:    tlsConfig,
		ReadTimeout:  self.settings.ProxyReadTimeout,
		WriteTimeout: self.settings.ProxyWriteTimeout,
		IdleTimeout:  self.settings.ProxyIdleTimeout,
		// see `ListenAndServe`: client-driven failures must not reach a log
		ErrorLog: discardLog,
		// see `ListenAndServe`: this is what lets shutdown reach a hijacked tunnel
		BaseContext: func(net.Listener) context.Context {
			return runCtx
		},
	}

	go connect.HandleError(func() {
		defer l.Close()
		defer httpServer.Close()
		select {
		case <-runCtx.Done():
		}
	})

	return httpServer.ServeTLS(l, "", "")
}

func (self *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// `http.ErrAbortHandler` is how a handler tells net/http to drop a response
	// whose head is already on the wire. `connect.HandleError` recovers every
	// panic, so it would swallow the sentinel and let a truncated body be framed
	// as a complete one; catch it here and re-raise it past the recover.
	var abort any
	connect.HandleError(func() {
		defer func() {
			if err := recover(); err != nil {
				if err == http.ErrAbortHandler {
					abort = err
					return
				}
				panic(err)
			}
		}()
		if r.Method == http.MethodConnect {
			self.handleHttps(w, r)
		} else {
			self.handleHttp(w, r)
		}
	})
	if abort != nil {
		panic(abort)
	}
}

func (self *HttpProxy) handleHttps(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	conn, clientRw, err := hij.Hijack()
	if err != nil {
		self.stats.ConnectHijackErrors.Add(1)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()
	// Close the hijacked conn when the handler ends or the proxy shuts down.
	// context.AfterFunc does not hold a goroutine while it waits (unlike a
	// `select { case <-ctx.Done(): }` watcher), and a goroutine's stack is the
	// largest per-connection memory item at scale.
	context.AfterFunc(handleCtx, func() {
		conn.Close()
	})

	// Anything net/http already buffered past the request belongs to the client's
	// stream (a client may pipeline bytes with the CONNECT rather than wait for
	// the 200). It must be taken now: see `drainBuffered`.
	buffered := drainBuffered(clientRw.Reader)

	// After Hijack, net/http no longer watches this connection: `hijackLocked`
	// aborts the background read whose failure would have canceled r.Context(),
	// and ServeHTTP has not returned, so the context is not canceled that way
	// either. Nothing else notices the client going away, so without an explicit
	// watch the dial retry below would never terminate for an unreachable
	// upstream — retrying forever and leaking this goroutine and the client fd.
	watch := watchClientClose(handleCtx, handleCancel, conn)

	// r.URL.Host contains both the host and port (if specified)
	var proxyConn net.Conn
	for {
		reconnect := connect.NewReconnect(self.proxyConnectTimeout())
		proxyConn, err = self.ConnectDialWithRequest(r, "tcp", r.URL.Host)
		if err == nil {
			break
		}
		self.stats.ConnectDialErrors.Add(1)
		select {
		case <-handleCtx.Done():
			// the client dropped the CONNECT, or the proxy is shutting down
			self.stats.ConnectClientsGone.Add(1)
			watch.stop()
			httpError(conn, http.StatusBadGateway, err)
			return
		case <-reconnect.After():
		}
	}
	defer proxyConn.Close()

	// End the watch before the data phase and recover anything the client sent
	// early: those bytes are the head of the tunnel's client stream, and dropping
	// them would hang a client that pipelined its ClientHello with the CONNECT.
	early := watch.stop()

	_, err = conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		return
	}

	clientReader := newClientConnReader(conn, buffered, early)
	copyRw(handleCtx, handleCancel, clientReader, conn, proxyConn, proxyConn, self.settings.ProxyReadTimeout, self.settings.ProxyWriteTimeout)
}

func (self *HttpProxy) handleHttp(w http.ResponseWriter, r *http.Request) {
	// r.Header.Del("Accept-Encoding")
	// r.Header.Del("Proxy-Connection")
	// r.Header.Del("Proxy-Authenticate")
	// r.Header.Del("Proxy-Authorization")

	b := bytes.NewBuffer(nil)
	bodyReader := io.Reader(r.Body)
	if 0 < self.settings.MaxHttpBodyBytes {
		bodyReader = io.LimitReader(r.Body, self.settings.MaxHttpBodyBytes+1)
	}
	_, err := copyBufferWithTimeout(r.Context(), b, bodyReader, self.settings.ProxyReadTimeout, self.settings.ProxyWriteTimeout)
	if closeErr := r.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if 0 < self.settings.MaxHttpBodyBytes && self.settings.MaxHttpBodyBytes < int64(b.Len()) {
		self.stats.BodiesTooLarge.Add(1)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	bodyBytes := b.Bytes()

	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()

	// dialFailed records that an attempt died before the request could reach the
	// origin, which makes the attempt safe to retry whatever the method.
	var dialFailed atomic.Bool

	tr := &http.Transport{
		Dial: func(network string, addr string) (net.Conn, error) {
			return connect.HandleError2(func() (net.Conn, error) {
				conn, err := self.ConnectDialWithRequest(r, network, addr)
				if err != nil {
					dialFailed.Store(true)
				}
				return conn, err
			}, func() (net.Conn, error) {
				dialFailed.Store(true)
				return nil, fmt.Errorf("Unexpected error")
			})
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   self.settings.ProxyTlsHandshakeTimeout,
		ResponseHeaderTimeout: self.settings.ProxyReadTimeout,
	}
	defer tr.CloseIdleConnections()

	var response *http.Response
	for {
		dialFailed.Store(false)
		r2 := cloneProxyRequest(handleCtx, r, bodyBytes)
		reconnect := connect.NewReconnect(self.proxyConnectTimeout())
		response, err = tr.RoundTrip(r2)
		if err == nil {
			break
		}
		if dialFailed.Load() {
			self.stats.RequestDialErrors.Add(1)
		}
		if !dialFailed.Load() && !isReplayable(r) {
			self.stats.RequestsNotReplayed.Add(1)
			// RoundTrip can fail after the request was fully sent, so a
			// non-idempotent request may already have taken effect at the origin.
			// Replaying it could duplicate that effect: fail instead of retrying.
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		select {
		case <-handleCtx.Done():
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		case <-reconnect.After():
		}
	}
	defer response.Body.Close()

	isUpgrade := response.StatusCode == http.StatusSwitchingProtocols
	proxyRw, isRw := response.Body.(io.ReadWriter)

	if isUpgrade && !isRw {
		self.stats.UpgradeErrors.Add(1)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	h := w.Header()
	for k := range w.Header() {
		h.Del(k)
	}
	for k, vs := range response.Header {
		h[k] = vs
	}
	w.WriteHeader(response.StatusCode)

	if isUpgrade {
		hij, ok := w.(http.Hijacker)
		if !ok {
			return
		}

		conn, clientRw, err := hij.Hijack()
		if err != nil {
			return
		}
		context.AfterFunc(handleCtx, func() {
			conn.Close()
		})

		// proxyRw is net/http's upgrade body: it supports no deadlines at all, so
		// the only thing that can unblock a read parked on it is closing it. The
		// relay does exactly that on cancellation — without it, this goroutine and
		// the upstream conn would leak permanently on every abandoned upgrade.
		clientReader := newClientConnReader(conn, drainBuffered(clientRw.Reader))
		copyRw(handleCtx, handleCancel, clientReader, conn, proxyRw, proxyRw, self.settings.ProxyReadTimeout, self.settings.ProxyWriteTimeout)
	} else {
		var flush func()

		// net/http moves Transfer-Encoding out of the header map and into
		// response.TransferEncoding, so testing the header for "chunked" never
		// matches and every streaming response would sit in the write buffer.
		streaming := slices.Contains(response.TransferEncoding, "chunked") ||
			response.ContentLength < 0 ||
			strings.HasPrefix(strings.ToLower(h.Get("content-type")), "text/event-stream")
		if streaming {
			if f, ok := w.(http.Flusher); ok {
				flush = f.Flush
			}
		}
		_, err := copyBufferWithTimeoutAndFlush(handleCtx, w, response.Body, self.settings.ProxyReadTimeout, self.settings.ProxyWriteTimeout, flush)
		if err != nil {
			// The head and part of the body are already on the wire, so an error
			// response can no longer be sent: http.Error would append its text to
			// the body the client is already reading, and for a chunked response
			// net/http would then frame that corrupted body as complete. Abort so
			// the client sees a truncated response instead of a silently wrong one.
			panic(http.ErrAbortHandler)
		}
	}
}

// isReplayable reports whether a failed request may be retried. It mirrors
// net/http's own replay rule: only methods without side effects, unless the
// caller explicitly marks the request idempotent.
func isReplayable(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	// non-standard, but widely used to mean "this POST is safe to retry"
	return r.Header.Get("Idempotency-Key") != "" || r.Header.Get("X-Idempotency-Key") != ""
}

// clientWatch watches a hijacked client connection for close while the proxy is
// still dialing upstream, and cancels the handler when the client goes away.
// net/http cannot do this for a hijacked connection (see handleHttps), and
// without it the dial retry has no exit.
//
// The watch reads from the client, so it also captures whatever the client sent
// early rather than waiting for the tunnel; stop returns those bytes so they can
// be replayed at the head of the tunnel instead of being lost.
type clientWatch struct {
	conn net.Conn
	done chan struct{}
	// stopping distinguishes the read error that `stop` induces on purpose from a
	// real client disconnect. Without it, ending the watch would look exactly like
	// the client going away and would cancel the tunnel it just established.
	stopping atomic.Bool
	early    []byte
}

// watchClientClose reads the raw hijacked conn, NOT the hijacked bufio.Reader:
// after a hijack net/http's connReader returns ErrHijacked for any read past
// what it had already buffered, which would look exactly like an instant client
// disconnect. The buffered bytes are taken separately, by `drainBuffered`.
func watchClientClose(ctx context.Context, cancel context.CancelFunc, conn net.Conn) *clientWatch {
	watch := &clientWatch{
		conn: conn,
		done: make(chan struct{}),
	}
	go connect.HandleError(func() {
		defer close(watch.done)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if 0 < n {
				watch.early = append(watch.early, buf[:n]...)
				if maxEarlyClientBytes <= len(watch.early) {
					// the client is demonstrably alive; stop buffering it
					return
				}
			}
			if err != nil {
				if !watch.stopping.Load() && ctx.Err() == nil {
					// the client dropped before the tunnel was established
					cancel()
				}
				return
			}
		}
	})
	return watch
}

// stop ends the watch and returns any bytes the client sent early. It is safe to
// call whether the watch is still blocked in a read or has already exited.
func (self *clientWatch) stop() []byte {
	self.stopping.Store(true)
	self.conn.SetReadDeadline(aLongTimeAgo)
	<-self.done
	self.conn.SetReadDeadline(time.Time{})
	return self.early
}

// drainBuffered takes the bytes net/http had already read from the client beyond
// the request itself. They must be recovered here: the hijacked bufio.Reader can
// only yield what it has buffered (reading past it hits net/http's connReader,
// which returns ErrHijacked), so the tunnel reads the rest of the stream from the
// raw conn and would otherwise drop these bytes entirely.
func drainBuffered(reader *bufio.Reader) []byte {
	n := reader.Buffered()
	if n == 0 {
		return nil
	}
	buffered := make([]byte, n)
	if _, err := io.ReadFull(reader, buffered); err != nil {
		return nil
	}
	return buffered
}

// clientConnReader is the tunnel's client-side reader: the bytes the client sent
// before the tunnel came up, followed by the rest of the connection. It keeps
// SetReadDeadline working (io.MultiReader does not forward it), which the relay
// needs both to apply read timeouts and to force a blocked read to return on
// teardown.
type clientConnReader struct {
	io.Reader
	conn net.Conn
}

func (self clientConnReader) SetReadDeadline(t time.Time) error {
	return self.conn.SetReadDeadline(t)
}

// newClientConnReader prepends the given byte chunks, in order, ahead of the
// connection itself.
func newClientConnReader(conn net.Conn, chunks ...[]byte) clientConnReader {
	readers := []io.Reader{}
	for _, chunk := range chunks {
		if 0 < len(chunk) {
			readers = append(readers, bytes.NewReader(chunk))
		}
	}
	if len(readers) == 0 {
		return clientConnReader{Reader: conn, conn: conn}
	}
	readers = append(readers, conn)
	return clientConnReader{Reader: io.MultiReader(readers...), conn: conn}
}

func cloneProxyRequest(ctx context.Context, r *http.Request, bodyBytes []byte) *http.Request {
	r2 := r.Clone(ctx)
	r2.RequestURI = ""
	r2.Header = r.Header.Clone()
	removeProxyRequestHeaders(r2.Header)
	if len(bodyBytes) == 0 {
		r2.Body = http.NoBody
		r2.GetBody = func() (io.ReadCloser, error) {
			return http.NoBody, nil
		}
		r2.ContentLength = 0
	} else {
		r2.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r2.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		r2.ContentLength = int64(len(bodyBytes))
	}
	return r2
}

func removeProxyRequestHeaders(h http.Header) {
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("Proxy-Connection")
}

// for a hijacked connection
func httpError(w io.Writer, statusCode int, err error) error {
	errorMessage := err.Error()
	errStr := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode,
		http.StatusText(statusCode),
		len(errorMessage),
		errorMessage,
	)
	_, writeErr := io.WriteString(w, errStr)
	return writeErr
}
