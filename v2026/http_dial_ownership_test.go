// Covers callback admission, late connection retirement and adjacent synchronous
// proxy paths with channel barriers and a joined, socket-free scheduler bubble.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// Observes actual connection retirement, including completion of a blocked
// Close, and counts duplicate underlying closes by transport and request owners.
type httpDialTestConn struct {
	net.Conn
	closeStarted chan struct{}
	releaseClose chan struct{}
	closed       chan struct{}
	closeCount   atomic.Int32
	closeOnce    sync.Once
}

// Blocks the first underlying close until the test releases it; all closes join.
func (self *httpDialTestConn) Close() error {
	self.closeCount.Add(1)
	self.closeOnce.Do(func() {
		close(self.closeStarted)
		<-self.releaseClose
		self.Conn.Close()
		close(self.closed)
	})
	return nil
}

// Every explicitly launched worker gets a fresh rescue bound, including on a
// failed primary assertion. The bubble also joins net/http's internal workers.
func joinHttpDialTestWorkers(t *testing.T, dones ...<-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, done := range dones {
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("released ownership test worker did not join")
		}
	}
	synctest.Wait()
}

// Requires a concrete event while keeping stalled setup distinct from the
// ownership assertion under test.
func awaitHttpDialTestEvent(t *testing.T, done <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("ownership test event did not occur")
	}
}

// Reads the actual drain level after scheduler quiescence, without a negative
// timing assertion. The already-canceled context only makes the read bounded.
func requireHttpDialTestActive(t *testing.T, proxy *HttpProxy) {
	t.Helper()
	synctest.Wait()
	proxy.Drain()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proxy.WaitIdle(ctx) || proxy.ActiveCount() != 1 {
		t.Errorf("request ownership ended before its dial resource retired (active=%d)", proxy.ActiveCount())
	}
}

// Checks a completed request without an unbounded wait even on a regression.
func requireHttpDialTestIdle(t *testing.T, proxy *HttpProxy) {
	t.Helper()
	proxy.Drain()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !proxy.WaitIdle(ctx) || proxy.ActiveCount() != 0 {
		t.Errorf("released request did not drain (active=%d)", proxy.ActiveCount())
	}
}

// A successful callback that ignores cancellation must close its connection
// before relinquishing the request, including the completion of a blocking Close.
func TestHttpProxyDrainRetainsLateSuccessfulDialClose(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		entered, release := make(chan struct{}), make(chan struct{})
		callbackDone, handlerDone := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		raw, peer := net.Pipe()
		conn := &httpDialTestConn{Conn: raw, closeStarted: make(chan struct{}), releaseClose: make(chan struct{}), closed: make(chan struct{})}
		unblockClose := sync.OnceFunc(func() { close(conn.releaseClose) })
		proxy := NewHttpProxy(DefaultHttpProxySettings())
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) {
			defer close(callbackDone)
			close(entered)
			<-release
			return conn, nil
		}
		go func() {
			defer close(handlerDone)
			proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "http://late-success.example/", nil))
		}()
		defer func() {
			cancel()
			unblock()
			unblockClose()
			peer.Close()
			joinHttpDialTestWorkers(t, callbackDone, conn.closed, handlerDone)
			requireHttpDialTestIdle(t, proxy)
			if calls := conn.closeCount.Load(); calls != 1 {
				t.Errorf("underlying connection closed %d times, want 1", calls)
			}
		}()
		awaitHttpDialTestEvent(t, entered)
		cancel()
		requireHttpDialTestActive(t, proxy)
		unblock()
		awaitHttpDialTestEvent(t, callbackDone)
		awaitHttpDialTestEvent(t, conn.closeStarted)
		requireHttpDialTestActive(t, proxy)
	})
}

// A callback may finish before the transport resumes to perform TLS setup. The
// request must retire that returned connection even with transport still held.
func TestHttpProxyDrainClosesDialBeforeTransportContinuation(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		transportEntered, releaseTransport := make(chan struct{}), make(chan struct{})
		transportDone, callbackDone, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		unblockTransport := sync.OnceFunc(func() { close(releaseTransport) })
		trace := &httptrace.ClientTrace{TLSHandshakeStart: func() {
			defer close(transportDone)
			close(transportEntered)
			<-releaseTransport
		}}
		ctx, cancel := context.WithCancel(httptrace.WithClientTrace(context.Background(), trace))
		raw, peer := net.Pipe()
		conn := &httpDialTestConn{Conn: raw, closeStarted: make(chan struct{}), releaseClose: make(chan struct{}), closed: make(chan struct{})}
		unblockClose := sync.OnceFunc(func() { close(conn.releaseClose) })
		proxy := NewHttpProxy(DefaultHttpProxySettings())
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) {
			defer close(callbackDone)
			return conn, nil
		}
		go func() {
			defer close(handlerDone)
			proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "https://held-transport.example/", nil))
		}()
		defer func() {
			cancel()
			unblockClose()
			unblockTransport()
			peer.Close()
			joinHttpDialTestWorkers(t, callbackDone, transportDone, conn.closed, handlerDone)
			if calls := conn.closeCount.Load(); calls != 1 {
				t.Errorf("underlying connection closed %d times, want 1", calls)
			}
		}()
		awaitHttpDialTestEvent(t, transportEntered)
		awaitHttpDialTestEvent(t, callbackDone)
		cancel()
		requireHttpDialTestActive(t, proxy)
		if calls := conn.closeCount.Load(); calls != 1 {
			t.Fatalf("request teardown started %d underlying closes while transport was held, want 1", calls)
		}
		unblockClose()
		awaitHttpDialTestEvent(t, conn.closed)
		awaitHttpDialTestEvent(t, handlerDone)
		requireHttpDialTestIdle(t, proxy)
	})
}

// A transport worker scheduled after the request is sealed must not enter the
// authentication callback, even if no earlier callback ever started.
func TestHttpDialOwnerRejectsLateTransportStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newHttpDialOwner(context.Background())
		release, workerDone := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		var calls atomic.Int32
		var dialErr error
		go func() {
			defer close(workerDone)
			<-release
			_, dialErr = owner.dial(func(context.Context) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("synthetic unexpected authentication")
			})
		}()
		defer func() {
			unblock()
			joinHttpDialTestWorkers(t, workerDone)
		}()
		owner.closeAndWait(func() {})
		unblock()
		awaitHttpDialTestEvent(t, workerDone)
		if calls.Load() != 0 || !errors.Is(dialErr, context.Canceled) {
			t.Errorf("late transport callback entered authentication %d times, err=%v", calls.Load(), dialErr)
		}
	})
}

// Supplies a controlled request body so drain begins after request admission
// and before its first transport callback is scheduled.
type httpDialTestBody struct {
	entered chan struct{}
	release chan struct{}
}

// Signals the body-read boundary and completes only after explicit release.
func (self *httpDialTestBody) Read([]byte) (int, error) {
	close(self.entered)
	<-self.release
	return 0, io.EOF
}

// The test body owns no resources beyond its joined read.
func (self *httpDialTestBody) Close() error { return nil }

// Graceful drain refuses new requests but still admits a first dial belonging
// to a request that was admitted before the drain began.
func TestHttpProxyDrainPreservesAdmittedPendingDial(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		body := &httpDialTestBody{entered: make(chan struct{}), release: make(chan struct{})}
		unblockBody := sync.OnceFunc(func() { close(body.release) })
		entered, release := make(chan struct{}), make(chan struct{})
		callbackDone, handlerDone := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		proxy := NewHttpProxy(DefaultHttpProxySettings())
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) {
			defer close(callbackDone)
			close(entered)
			<-release
			return nil, context.Canceled
		}
		request := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://pending-dial.example/", nil)
		request.Body = body
		go func() {
			defer close(handlerDone)
			proxy.ServeHTTP(httptest.NewRecorder(), request)
		}()
		defer func() {
			cancel()
			unblockBody()
			unblock()
			joinHttpDialTestWorkers(t, callbackDone, handlerDone)
		}()
		awaitHttpDialTestEvent(t, body.entered)
		proxy.Drain()
		refused := httptest.NewRecorder()
		proxy.ServeHTTP(refused, httptest.NewRequest(http.MethodGet, "http://new-request.example/", nil))
		if refused.Code != http.StatusServiceUnavailable {
			t.Errorf("new request status = %d, want 503", refused.Code)
		}
		unblockBody()
		awaitHttpDialTestEvent(t, entered)
		requireHttpDialTestActive(t, proxy)
	})
}

// An unrelated proxy must keep owning and serving its request when another
// proxy drains and cancels its independently owned transport callback.
func TestHttpProxyDetachedDialsHaveIndependentOwners(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		type requestOwner struct {
			proxy        *HttpProxy
			cancel       context.CancelFunc
			entered      chan struct{}
			release      chan struct{}
			callbackDone chan struct{}
			handlerDone  chan struct{}
			unblock      func()
			dialCtx      context.Context
		}
		owners := make([]*requestOwner, 0, 2)
		defer func() {
			for _, owner := range owners {
				owner.cancel()
				owner.unblock()
			}
			for _, owner := range owners {
				joinHttpDialTestWorkers(t, owner.callbackDone, owner.handlerDone)
			}
		}()
		for range 2 {
			ctx, cancel := context.WithCancel(context.Background())
			owner := &requestOwner{proxy: NewHttpProxy(DefaultHttpProxySettings()), cancel: cancel, entered: make(chan struct{}), release: make(chan struct{}), callbackDone: make(chan struct{}), handlerDone: make(chan struct{})}
			owner.unblock = sync.OnceFunc(func() { close(owner.release) })
			owners = append(owners, owner)
			owner.proxy.ConnectDialContextWithRequest = func(ctx context.Context, _ *http.Request, _, _ string) (net.Conn, error) {
				defer close(owner.callbackDone)
				owner.dialCtx = ctx
				close(owner.entered)
				<-owner.release
				return nil, context.Canceled
			}
			go func() {
				defer close(owner.handlerDone)
				owner.proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "http://independent-owner.example/", nil))
			}()
			awaitHttpDialTestEvent(t, owner.entered)
		}
		owners[0].cancel()
		requireHttpDialTestActive(t, owners[0].proxy)
		owners[0].unblock()
		awaitHttpDialTestEvent(t, owners[0].handlerDone)
		requireHttpDialTestIdle(t, owners[0].proxy)
		if err := owners[1].dialCtx.Err(); err != nil {
			t.Errorf("first proxy canceled independent dial: %v", err)
		}
		if active := owners[1].proxy.ActiveCount(); active != 1 {
			t.Errorf("independent proxy active count = %d, want 1", active)
		}
	})
}

// Gives the actual CONNECT handler a channel-backed connection to hijack.
type httpDialTestHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

// Transfers the channel-backed client connection to the actual handler.
func (self *httpDialTestHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return self.conn, bufio.NewReadWriter(bufio.NewReader(self.conn), bufio.NewWriter(self.conn)), nil
}

// CONNECT calls the dial callback synchronously, so its original handler
// lifetime already retains admission while an ignoring callback is held.
func TestHttpProxyConnectRetainsSynchronousDial(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client, peer := net.Pipe()
		entered, release := make(chan struct{}), make(chan struct{})
		callbackDone, handlerDone := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		proxy := NewHttpProxy(DefaultHttpProxySettings())
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) {
			defer close(callbackDone)
			close(entered)
			<-release
			return nil, context.Canceled
		}
		go func() {
			defer close(handlerDone)
			proxy.ServeHTTP(&httpDialTestHijacker{ResponseRecorder: httptest.NewRecorder(), conn: client}, httptest.NewRequestWithContext(ctx, http.MethodConnect, "https://connect-control.example:443", nil))
		}()
		defer func() {
			cancel()
			unblock()
			client.Close()
			peer.Close()
			joinHttpDialTestWorkers(t, callbackDone, handlerDone)
		}()
		awaitHttpDialTestEvent(t, entered)
		cancel()
		requireHttpDialTestActive(t, proxy)
	})
}

// SOCKS also calls its dial synchronously within one counted session; request
// cancellation cannot let WaitIdle pass while that callback remains held.
func TestSocksProxyRetainsSynchronousDial(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		serverConn, clientConn := net.Pipe()
		entered, release := make(chan struct{}), make(chan struct{})
		callbackDone, serverDone, clientDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		proxy := NewSocksProxy(DefaultSocksProxySettings())
		proxy.ConnectDialWithRequest = func(context.Context, SocksRequest, string, string) (net.Conn, error) {
			defer close(callbackDone)
			close(entered)
			<-release
			return nil, context.Canceled
		}
		go func() {
			defer close(serverDone)
			proxy.ensureServer().ServeConn(ctx, serverConn)
		}()
		go func() {
			defer close(clientDone)
			if _, err := clientConn.Write([]byte{socksVersion, 1, methodNoAuth}); err != nil {
				return
			}
			var reply [2]byte
			if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
				return
			}
			request := appendAddrSpec([]byte{socksVersion, cmdConnect, 0}, &AddrSpec{FQDN: "socks-control.example", Port: 443})
			clientConn.Write(request)
			io.Copy(io.Discard, clientConn)
		}()
		defer func() {
			cancel()
			unblock()
			serverConn.Close()
			clientConn.Close()
			joinHttpDialTestWorkers(t, callbackDone, serverDone, clientDone)
		}()
		awaitHttpDialTestEvent(t, entered)
		cancel()
		synctest.Wait()
		proxy.Drain()
		bound, stop := context.WithCancel(context.Background())
		stop()
		if proxy.WaitIdle(bound) || proxy.ActiveCount() != 1 {
			t.Errorf("socks callback lost its synchronous session ownership (active=%d)", proxy.ActiveCount())
		}
	})
}
