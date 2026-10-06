// Forces shutdown order at the actual serving and relay scopes with durable barriers.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect"
)

// Embedding binds the route check to exactly the source used by this compilation.
//
//go:embed http.go
var ownershipHttpSource string

//go:embed socks5_server.go
var ownershipSocksSource string

//go:embed socks5_associate.go
var ownershipAssociateSource string

// Implements a listener whose accept and close states are entirely test-owned.
type ownershipListener struct {
	conns        chan net.Conn
	acceptErrors chan error
	closed       chan struct{}
	closeOnce    sync.Once
	closeEntered chan struct{}
	closeRelease chan struct{}
}

// Constructs a listener with no external sockets or background worker.
func newOwnershipListener() *ownershipListener {
	return &ownershipListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
}

// Accepts one test-owned connection or the listener's terminal close event.
func (self *ownershipListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case err := <-self.acceptErrors:
		return nil, err
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

// Releases Accept before an optional held close tail to expose premature returns.
func (self *ownershipListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
		if self.closeEntered != nil {
			close(self.closeEntered)
			<-self.closeRelease
		}
	})
	return nil
}

// Provides visibly synthetic addressing without opening a network socket.
func (self *ownershipListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}
}

// Holds logger work across context cancellation without changing the logger API.
type ownershipLogger struct {
	connect.Logger
	entered chan struct{}
	release chan struct{}
}

// Signals the synchronous log call before holding its completion.
func (self *ownershipLogger) Infof(string, ...any) {
	close(self.entered)
	<-self.release
}

// Gives each test isolated counters and no default logger output.
func ownershipHttpSettings() *HttpProxySettings {
	settings := DefaultHttpProxySettings()
	settings.StatsLogInterval = 0
	settings.Log = connect.NewNoopLogger()
	return settings
}

// Gives each test isolated counters and no default logger output.
func ownershipSocksSettings() *SocksProxySettings {
	settings := DefaultSocksProxySettings()
	settings.StatsLogInterval = 0
	settings.HandshakeTimeout = 0
	settings.Log = connect.NewNoopLogger()
	return settings
}

// Uses synctest's durable quiescence instead of timing assumptions for the negative check.
func ownershipMustStillRun(t *testing.T, done <-chan error, what string) bool {
	t.Helper()
	synctest.Wait()
	select {
	case err := <-done:
		t.Errorf("%s returned before its held worker completed: %v", what, err)
		return false
	default:
		return true
	}
}

// Public listener entry points must execute the same body tested by synthetic listeners.
func TestServeOwnershipPublicRoutesToServingScopes(t *testing.T) {
	for _, source := range []struct {
		source  string
		methods []string
		target  string
	}{
		{source: ownershipHttpSource, methods: []string{"ListenAndServe", "ListenAndServeTls"}, target: "serve"},
		{source: ownershipSocksSource, methods: []string{"ListenAndServe"}, target: "serve"},
		{source: ownershipAssociateSource, methods: []string{"handleAssociate"}, target: "serveAssociate"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "serving.go", source.source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range source.methods {
			found := false
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != method {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == source.target {
						found = true
					}
					return true
				})
			}
			if !found {
				t.Errorf("%s bypasses the tested serving scope", method)
			}
		}
	}
}

// A tls configuration callback precedes ServeHTTP and must still hold shutdown open.
func TestServeOwnershipHttpJoinsTlsCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		proxy := NewHttpProxy(ownershipHttpSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener := newOwnershipListener()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		listener.conns <- serverConn
		entered := make(chan struct{})
		release := make(chan struct{})
		server := &http.Server{Handler: proxy, ErrorLog: discardLog, TLSConfig: &tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				close(entered)
				<-release
				return nil, errors.New("synthetic certificate rejection")
			},
		}}
		done := make(chan error, 1)
		go func() { done <- proxy.serve(ctx, listener, server) }()
		clientDone := make(chan error, 1)
		go func() {
			client := tls.Client(clientConn, &tls.Config{ServerName: "serve-owner.example", InsecureSkipVerify: true})
			clientDone <- client.Handshake()
		}()
		<-entered
		if got := proxy.ActiveCount(); got != 0 {
			t.Errorf("pre-handler callback changed ActiveCount to %d", got)
		}
		proxy.Drain()
		if !proxy.WaitIdle(context.Background()) {
			t.Error("pre-handler ownership must not change graceful idle accounting")
		}
		draining := ownershipMustStillRun(t, done, "graceful tls drain")
		cancel()
		waiting := false
		if draining {
			waiting = ownershipMustStillRun(t, done, "tls serving")
		}
		close(release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		<-clientDone
		listener.Close()
	})
}

// A preserved terminal ConnState callback belongs to connection completion.
func TestServeOwnershipHttpJoinsTerminalHook(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		proxy := NewHttpProxy(ownershipHttpSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener := newOwnershipListener()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		listener.conns <- serverConn
		entered := make(chan struct{})
		release := make(chan struct{})
		server := &http.Server{Handler: proxy, ErrorLog: discardLog, ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				close(entered)
				<-release
			}
		}}
		done := make(chan error, 1)
		go func() { done <- proxy.serve(ctx, listener, server) }()
		clientConn.Close()
		<-entered
		cancel()
		waiting := ownershipMustStillRun(t, done, "terminal connection hook")
		close(release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		listener.Close()
	})
}

// A synchronous logger call must be complete before its per-serve owner returns.
func TestServeOwnershipHttpJoinsStats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := &ownershipLogger{Logger: connect.NewNoopLogger(), entered: make(chan struct{}), release: make(chan struct{})}
		settings := ownershipHttpSettings()
		settings.Log = logger
		settings.StatsLogInterval = time.Second
		proxy := NewHttpProxy(settings)
		proxy.stats.RequestDialErrors.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener := newOwnershipListener()
		done := make(chan error, 1)
		go func() { done <- proxy.serve(ctx, listener, &http.Server{Handler: proxy, ErrorLog: discardLog}) }()
		<-logger.entered
		cancel()
		waiting := ownershipMustStillRun(t, done, "http stats")
		close(logger.release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		listener.Close()
	})
}

// A listener's close method may release Accept before finishing its own cleanup.
func TestServeOwnershipSocksJoinsCloseWatcher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newSocksServer(ownershipSocksSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener := newOwnershipListener()
		listener.closeEntered = make(chan struct{})
		listener.closeRelease = make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- server.serve(ctx, listener) }()
		synctest.Wait()
		cancel()
		<-listener.closeEntered
		waiting := ownershipMustStillRun(t, done, "socks listener watcher")
		close(listener.closeRelease)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		listener.Close()
	})
}

// A direct session with no handshake timeout must still observe owner cancellation.
func TestServeOwnershipSocksCancelsUnfinishedHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newSocksServer(ownershipSocksSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		done := make(chan error, 1)
		go func() { done <- server.ServeConn(ctx, serverConn) }()
		synctest.Wait()
		if got := server.drain.ActiveCount(); got != 1 {
			t.Errorf("session admission = %d", got)
		}
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("canceled socks session remains in an unbounded handshake read")
			clientConn.Close()
			<-done
		}
		if got := server.drain.ActiveCount(); got != 0 {
			t.Errorf("finished session admission = %d", got)
		}
	})
}

// Exposes an accepted session whose final connection close is still running.
type ownershipCloseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// Closes the pipe before retaining a deterministic provider-wrapper cleanup tail.
func (self *ownershipCloseConn) Close() error {
	self.once.Do(func() {
		self.Conn.Close()
		close(self.entered)
		<-self.release
	})
	return nil
}

// Accepted session completion includes the provider connection's full Close return.
func TestServeOwnershipSocksJoinsAcceptedSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newSocksServer(ownershipSocksSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener := newOwnershipListener()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		ownedConn := &ownershipCloseConn{Conn: serverConn, entered: make(chan struct{}), release: make(chan struct{})}
		listener.conns <- ownedConn
		done := make(chan error, 1)
		go func() { done <- server.serve(ctx, listener) }()
		synctest.Wait()
		if got := server.drain.ActiveCount(); got != 1 {
			t.Errorf("session admission = %d", got)
		}
		clientConn.Close()
		<-ownedConn.entered
		cancel()
		waiting := ownershipMustStillRun(t, done, "accepted socks session")
		close(ownedConn.release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		listener.Close()
	})
}

// Holds the cancellation deadline callback independently of both relay directions.
type ownershipRelayReader struct {
	readEntered chan struct{}
	readRelease chan struct{}
	tailEntered chan struct{}
	tailRelease chan struct{}
	tailDone    chan struct{}
}

// Reads no bytes; completion is driven by a dedicated barrier.
func (self *ownershipRelayReader) Read([]byte) (int, error) {
	close(self.readEntered)
	<-self.readRelease
	return 0, io.EOF
}

// Only the cancellation callback sets a deadline because read timeouts are disabled.
func (self *ownershipRelayReader) SetReadDeadline(time.Time) error {
	if self.tailEntered != nil {
		close(self.tailEntered)
		<-self.tailRelease
		close(self.tailDone)
	}
	return nil
}

// Avoids process-global pool workers inside a synctest bubble.
type ownershipBuffers struct{}

// Returns a bounded test-owned copy buffer.
func (self ownershipBuffers) Get() []byte { return make([]byte, relayBufferSize) }

// The garbage collector owns these unpooled test buffers.
func (self ownershipBuffers) Put([]byte) {}

// Both copy directions can finish while the forced-close callback is still running.
func TestServeOwnershipRelayJoinsCancellationTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a := &ownershipRelayReader{readEntered: make(chan struct{}), readRelease: make(chan struct{}), tailEntered: make(chan struct{}), tailRelease: make(chan struct{}), tailDone: make(chan struct{})}
		b := &ownershipRelayReader{readEntered: make(chan struct{}), readRelease: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: a, Writer: io.Discard}, relayEndpoint{Reader: b, Writer: io.Discard}, relayConfig{Buffers: ownershipBuffers{}})
		}()
		<-a.readEntered
		<-b.readEntered
		cancel()
		<-a.tailEntered
		close(a.readRelease)
		close(b.readRelease)
		waiting := ownershipMustStillRun(t, done, "relay cancellation tail")
		close(a.tailRelease)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		<-a.tailDone
	})
}

// A singleton flusher must be joined after all serve attempts and shared cancellation.
func TestServeOwnershipSocksWaitStatsAfterBindError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := &ownershipLogger{Logger: connect.NewNoopLogger(), entered: make(chan struct{}), release: make(chan struct{})}
		settings := ownershipSocksSettings()
		settings.Log = logger
		settings.StatsLogInterval = time.Second
		proxy := NewSocksProxy(settings)
		proxy.ensureServer().stats.ConnectDialErrors.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// A bind failure must return while its shared serving context remains live.
		if err := proxy.ListenAndServe(ctx, "synthetic-invalid-network", ""); err == nil {
			t.Error("missing bind error")
		}
		<-logger.entered
		cancel()
		done := make(chan error, 1)
		go func() {
			var err error
			if waiter, ok := any(proxy).(interface{ WaitStats(context.Context) error }); ok {
				err = waiter.WaitStats(context.Background())
			}
			done <- err
		}()
		waiting := ownershipMustStillRun(t, done, "socks stats lifecycle")
		close(logger.release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	})
}

// The same helper is reused by connection tests that serve a hijacked response.
type ownershipHijackWriter struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	hijacked chan struct{}
}

// Supplies the owned pipe without starting an unrelated http server.
func (self *ownershipHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if self.hijacked != nil {
		close(self.hijacked)
	}
	return self.conn, bufio.NewReadWriter(bufio.NewReader(self.conn), bufio.NewWriter(self.conn)), nil
}

// A normal handler return must synchronously retire its hijacked socket close tail.
func TestServeOwnershipConnectJoinsSocketClose(t *testing.T) {
	buffer := connect.MessagePoolGet(relayBufferSize)
	connect.MessagePoolReturn(buffer)
	synctest.Test(t, func(t *testing.T) {
		proxy := NewHttpProxy(ownershipHttpSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		ownedConn := &ownershipCloseConn{Conn: serverConn, entered: make(chan struct{}), release: make(chan struct{})}
		dialEntered := make(chan struct{})
		proxy.ConnectDialContextWithRequest = func(ctx context.Context, _ *http.Request, _, _ string) (net.Conn, error) {
			close(dialEntered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		request := httptest.NewRequest(http.MethodConnect, "http://connect-owner.example:443", nil).WithContext(ctx)
		writer := &ownershipHijackWriter{ResponseRecorder: httptest.NewRecorder(), conn: ownedConn}
		done := make(chan error, 1)
		go func() { proxy.ServeHTTP(writer, request); done <- nil }()
		<-dialEntered
		cancel()
		<-ownedConn.entered
		waiting := ownershipMustStillRun(t, done, "connect close tail")
		close(ownedConn.release)
		if waiting {
			<-done
		}
		if got := proxy.ActiveCount(); got != 0 {
			t.Errorf("finished handler admission = %d", got)
		}
	})
}

// A startup error is neither swallowed nor rewritten as a clean cancellation.
func TestServeOwnershipPublicStartupErrors(t *testing.T) {
	ctx := context.Background()
	httpProxy := NewHttpProxy(ownershipHttpSettings())
	for _, serve := range []func(context.Context, string, string) error{httpProxy.ListenAndServe, httpProxy.ListenAndServeTls} {
		if err := serve(ctx, "synthetic-invalid-network", ""); err == nil || !strings.Contains(err.Error(), "unknown network") {
			t.Errorf("startup error = %v", err)
		}
	}
}

// A real accept error survives joined teardown on both protocol paths.
func TestServeOwnershipPreservesAcceptErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, protocol := range []string{"http", "socks"} {
			listener := newOwnershipListener()
			listener.acceptErrors = make(chan error, 1)
			failure := errors.New("synthetic accept failure")
			listener.acceptErrors <- failure
			var err error
			if protocol == "http" {
				proxy := NewHttpProxy(ownershipHttpSettings())
				err = proxy.serve(context.Background(), listener, &http.Server{Handler: proxy, ErrorLog: discardLog})
			} else {
				err = newSocksServer(ownershipSocksSettings()).serve(context.Background(), listener)
			}
			if !errors.Is(err, failure) {
				t.Errorf("%s accept error = %v", protocol, err)
			}
			listener.Close()
		}
	})
}

// Closing one independent instance must not wait for another's blocked logger.
func TestServeOwnershipIndependentHttpInstances(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := &ownershipLogger{Logger: connect.NewNoopLogger(), entered: make(chan struct{}), release: make(chan struct{})}
		settings := ownershipHttpSettings()
		settings.Log = logger
		settings.StatsLogInterval = time.Second
		first := NewHttpProxy(settings)
		first.stats.RequestDialErrors.Add(1)
		firstCtx, firstCancel := context.WithCancel(context.Background())
		defer firstCancel()
		firstListener := newOwnershipListener()
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- first.serve(firstCtx, firstListener, &http.Server{Handler: first, ErrorLog: discardLog})
		}()
		<-logger.entered
		second := NewHttpProxy(ownershipHttpSettings())
		secondCtx, secondCancel := context.WithCancel(context.Background())
		defer secondCancel()
		secondListener := newOwnershipListener()
		secondDone := make(chan error, 1)
		go func() {
			secondDone <- second.serve(secondCtx, secondListener, &http.Server{Handler: second, ErrorLog: discardLog})
		}()
		synctest.Wait()
		secondCancel()
		if err := <-secondDone; err != nil {
			t.Error(err)
		}
		firstCancel()
		waiting := ownershipMustStillRun(t, firstDone, "first independent http stats")
		close(logger.release)
		if waiting {
			if err := <-firstDone; err != nil {
				t.Error(err)
			}
		}
		firstListener.Close()
		secondListener.Close()
	})
}

// Shared flusher waits are bounded, retryable, and isolated across proxy instances.
func TestServeOwnershipSocksStatsWaitBoundsAndIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := &ownershipLogger{Logger: connect.NewNoopLogger(), entered: make(chan struct{}), release: make(chan struct{})}
		settings := ownershipSocksSettings()
		settings.Log = logger
		settings.StatsLogInterval = time.Second
		first := NewSocksProxy(settings)
		waiter, ok := any(first).(interface{ WaitStats(context.Context) error })
		if !ok {
			t.Fatal("socks proxy has no stats completion API")
		}
		if err := waiter.WaitStats(context.Background()); err != nil {
			t.Errorf("unstarted stats = %v", err)
		}
		first.ensureServer().stats.ConnectDialErrors.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := first.ListenAndServe(ctx, "synthetic-invalid-network", ""); err == nil {
			t.Error("missing bind error")
		}
		<-logger.entered
		cancel()
		expired, expire := context.WithCancel(context.Background())
		expire()
		if err := waiter.WaitStats(expired); !errors.Is(err, context.Canceled) {
			t.Errorf("bound wait = %v", err)
		}
		second := NewSocksProxy(ownershipSocksSettings())
		secondWaiter, ok := any(second).(interface{ WaitStats(context.Context) error })
		if !ok {
			t.Error("second instance missing stats completion API")
		} else if err := secondWaiter.WaitStats(context.Background()); err != nil {
			t.Errorf("independent stats = %v", err)
		}
		close(logger.release)
		if err := waiter.WaitStats(context.Background()); err != nil {
			t.Errorf("retried stats = %v", err)
		}
		if err := waiter.WaitStats(expired); err != nil {
			t.Errorf("finished stats should win over expired bound: %v", err)
		}
	})
}

// A hijacked connection transfers shutdown ownership to the still-running handler.
func TestServeOwnershipHttpJoinsHijackedHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		proxy := NewHttpProxy(ownershipHttpSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener := newOwnershipListener()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		listener.conns <- serverConn
		entered := make(chan struct{})
		release := make(chan struct{})
		server := &http.Server{ErrorLog: discardLog, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				close(entered)
				return
			}
			defer conn.Close()
			close(entered)
			<-release
		})}
		done := make(chan error, 1)
		go func() { done <- proxy.serve(ctx, listener, server) }()
		writeDone := make(chan error, 1)
		go func() {
			_, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: serving-owner.example\r\n\r\n")
			writeDone <- err
		}()
		<-entered
		if err := <-writeDone; err != nil {
			t.Error(err)
		}
		cancel()
		waiting := ownershipMustStillRun(t, done, "hijacked handler")
		close(release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		listener.Close()
	})
}

// A datagram reader with no external network makes every wait durably observable.
type ownershipDatagramRelay struct {
	closed chan struct{}
	once   sync.Once
}

// Retains the association's single datagram reader until teardown closes it.
func (self *ownershipDatagramRelay) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	<-self.closed
	return 0, nil, net.ErrClosed
}

// No payloads are generated in this lifecycle-only fixture.
func (self *ownershipDatagramRelay) WriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	return len(data), nil
}

// Releases the owned datagram reader once.
func (self *ownershipDatagramRelay) Close() error {
	self.once.Do(func() { close(self.closed) })
	return nil
}

// Holds a provider's deadline-method tail after the control read is unblocked.
type ownershipDeadlineConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
}

// Makes cancellation observable to Read before retaining callback completion.
func (self *ownershipDeadlineConn) SetReadDeadline(deadline time.Time) error {
	err := self.Conn.SetReadDeadline(deadline)
	close(self.entered)
	<-self.release
	close(self.done)
	return err
}

// Datagram and flow joins do not imply a deadline cancellation callback has returned.
func TestServeOwnershipAssociateJoinsDeadlineTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newSocksServer(ownershipSocksSettings())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()
		conn := &ownershipDeadlineConn{Conn: serverConn, entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
		relay := &ownershipDatagramRelay{closed: make(chan struct{})}
		done := make(chan error, 1)
		go func() { done <- server.serveAssociate(ctx, conn, &Request{}, relay) }()
		synctest.Wait()
		cancel()
		<-conn.entered
		waiting := ownershipMustStillRun(t, done, "associate deadline tail")
		close(conn.release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		<-conn.done
		relay.Close()
	})
}

// Holds the handler's first Close while letting the separately owned relay close finish.
type ownershipUpgradeConn struct {
	net.Conn
	closeEntered    chan struct{}
	closeRelease    chan struct{}
	deadlineEntered chan struct{}
	deadlineRelease chan struct{}
	closeCalls      atomic.Int64
	deadlineOnce    sync.Once
}

// Only the handler callback can reach the first close before the relay deadline gate opens.
func (self *ownershipUpgradeConn) Close() error {
	err := self.Conn.Close()
	if self.closeCalls.Add(1) == 1 {
		close(self.closeEntered)
		<-self.closeRelease
	}
	return err
}

// Holds relayForceUnblock before its own Close, separating the two cleanup owners.
func (self *ownershipUpgradeConn) SetReadDeadline(deadline time.Time) error {
	if deadline.Equal(aLongTimeAgo) {
		self.deadlineOnce.Do(func() { close(self.deadlineEntered); <-self.deadlineRelease })
	}
	return self.Conn.SetReadDeadline(deadline)
}

// Joining the relay callback alone cannot retire the upgrade handler's independent Close callback.
func TestServeOwnershipUpgradeJoinsSocketClose(t *testing.T) {
	buffer := connect.MessagePoolGet(relayBufferSize)
	connect.MessagePoolReturn(buffer)
	synctest.Test(t, func(t *testing.T) {
		settings := ownershipHttpSettings()
		settings.ProxyReadTimeout = 0
		settings.ProxyWriteTimeout = 0
		proxy := NewHttpProxy(settings)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		ownedConn := &ownershipUpgradeConn{Conn: serverConn, closeEntered: make(chan struct{}), closeRelease: make(chan struct{}), deadlineEntered: make(chan struct{}), deadlineRelease: make(chan struct{})}
		upstreamConn, originConn := net.Pipe()
		defer originConn.Close()
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) { return upstreamConn, nil }
		originDone := make(chan error, 1)
		go func() {
			request, err := http.ReadRequest(bufio.NewReader(originConn))
			if err != nil {
				originDone <- err
				return
			}
			request.Body.Close()
			_, err = io.WriteString(originConn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: synthetic\r\n\r\n")
			originDone <- err
		}()
		request := httptest.NewRequest(http.MethodGet, "http://upgrade-owner.example/", nil).WithContext(ctx)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "synthetic")
		writer := &ownershipHijackWriter{ResponseRecorder: httptest.NewRecorder(), conn: ownedConn, hijacked: make(chan struct{})}
		done := make(chan error, 1)
		go func() { proxy.ServeHTTP(writer, request); done <- nil }()
		<-writer.hijacked
		if err := <-originDone; err != nil {
			t.Error(err)
		}
		synctest.Wait()
		cancel()
		<-ownedConn.closeEntered
		<-ownedConn.deadlineEntered
		close(ownedConn.deadlineRelease)
		waiting := ownershipMustStillRun(t, done, "upgrade close tail")
		close(ownedConn.closeRelease)
		if waiting {
			<-done
		}
		upstreamConn.Close()
		ownedConn.Close()
	})
}
