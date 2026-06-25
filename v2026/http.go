package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	// "sync"
	"bytes"

	"github.com/urnetwork/connect/v2026"
)

// a simple http/https proxy focused on proper file descriptor management

type HttpProxy struct {
	ProxyReadTimeout    time.Duration
	ProxyWriteTimeout   time.Duration
	ProxyIdleTimeout    time.Duration
	ProxyConnectTimeout time.Duration
	// only used for http proxy
	ProxyTlsHandshakeTimeout time.Duration
	MaxHttpBodyBytes         int64
	ConnectDialWithRequest   func(r *http.Request, network string, addr string) (net.Conn, error)
	GetTlsConfigForClient    func(*tls.ClientHelloInfo) (*tls.Config, error)
}

func NewHttpProxy() *HttpProxy {
	return &HttpProxy{
		MaxHttpBodyBytes: 2 * 1024 * 1024,
	}
}

func (self *HttpProxy) ListenAndServe(ctx context.Context, network string, addr string) error {

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      self,
		ReadTimeout:  self.ProxyReadTimeout,
		WriteTimeout: self.ProxyWriteTimeout,
		IdleTimeout:  self.ProxyIdleTimeout,
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

	go connect.HandleError(func() {
		defer l.Close()
		defer httpServer.Close()
		select {
		case <-runCtx.Done():
		}
	})

	return httpServer.Serve(l)
}

func (self *HttpProxy) ListenAndServeTls(ctx context.Context, network string, addr string) error {

	tlsConfig := &tls.Config{
		GetConfigForClient: self.GetTlsConfigForClient,
	}

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      self,
		TLSConfig:    tlsConfig,
		ReadTimeout:  self.ProxyReadTimeout,
		WriteTimeout: self.ProxyWriteTimeout,
		IdleTimeout:  self.ProxyIdleTimeout,
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
	connect.HandleError(func() {
		if r.Method == http.MethodConnect {
			self.handleHttps(w, r)
		} else {
			self.handleHttp(w, r)
		}
	})
}

func (self *HttpProxy) handleHttps(w http.ResponseWriter, r *http.Request) {
	hij := w.(http.Hijacker)

	conn, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()
	go connect.HandleError(func() {
		defer conn.Close()
		select {
		case <-handleCtx.Done():
		}
	})

	// r.URL.Host contains both the host and port (if specified)
	var proxyConn net.Conn
	for {
		reconnect := connect.NewReconnect(self.ProxyConnectTimeout)
		proxyConn, err = self.ConnectDialWithRequest(r, "tcp", r.URL.Host)
		if err == nil {
			break
		}
		select {
		case <-handleCtx.Done():
			httpError(conn, http.StatusBadGateway, err)
			return
		case <-reconnect.After():
		}
	}
	defer proxyConn.Close()

	_, err = conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		return
	}

	copyConn(handleCtx, handleCancel, conn, proxyConn, self.ProxyReadTimeout, self.ProxyWriteTimeout)
}

func (self *HttpProxy) handleHttp(w http.ResponseWriter, r *http.Request) {
	// r.Header.Del("Accept-Encoding")
	// r.Header.Del("Proxy-Connection")
	// r.Header.Del("Proxy-Authenticate")
	// r.Header.Del("Proxy-Authorization")

	b := bytes.NewBuffer(nil)
	bodyReader := io.Reader(r.Body)
	if 0 < self.MaxHttpBodyBytes {
		bodyReader = io.LimitReader(r.Body, self.MaxHttpBodyBytes+1)
	}
	_, err := copyBufferWithTimeout(b, bodyReader, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
	if closeErr := r.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if 0 < self.MaxHttpBodyBytes && self.MaxHttpBodyBytes < int64(b.Len()) {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	bodyBytes := b.Bytes()

	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()

	tr := &http.Transport{
		Dial: func(network string, addr string) (net.Conn, error) {
			return connect.HandleError2(func() (net.Conn, error) {
				return self.ConnectDialWithRequest(r, network, addr)
			}, func() (net.Conn, error) {
				return nil, fmt.Errorf("Unexpected error")
			})
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   self.ProxyTlsHandshakeTimeout,
		ResponseHeaderTimeout: self.ProxyReadTimeout,
	}

	var response *http.Response
	for {
		r2 := cloneProxyRequest(handleCtx, r, bodyBytes)
		reconnect := connect.NewReconnect(self.ProxyConnectTimeout)
		response, err = tr.RoundTrip(r2)
		if err == nil {
			break
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

		conn, _, err := hij.Hijack()
		if err != nil {
			return
		}
		go connect.HandleError(func() {
			defer conn.Close()
			select {
			case <-handleCtx.Done():
			}
		})

		copyConn(handleCtx, handleCancel, conn, proxyRw, self.ProxyReadTimeout, self.ProxyWriteTimeout)
	} else {
		var flush func()

		chunked := false
		if strings.HasPrefix(strings.ToLower(h.Get("content-type")), "text/event-stream") {
			chunked = true
		}
		if strings.Contains(strings.ToLower(h.Get("transfer-encoding")), "chunked") {
			chunked = true
		}
		if chunked {
			if f, ok := w.(http.Flusher); ok {
				flush = f.Flush
			}
		}
		_, err := copyBufferWithTimeoutAndFlush(w, response.Body, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout, flush)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		}
	}
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
