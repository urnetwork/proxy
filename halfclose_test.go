package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// halfCloseBackend reads the request until the peer's write side closes, and only
// THEN answers. This is the "send request, shut down the write side, read the
// response" idiom: it can only work if the proxy propagates the half-close rather
// than tearing the whole tunnel down on the client's FIN.
//
// The idiom does not occur in HTTP — a request body is always self-delimiting, so
// an HTTP client never needs a FIN to mark the end of its request — but it is
// common in the arbitrary TCP a SOCKS proxy carries.
func halfCloseBackend(t *testing.T) string {
	return listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(io.Discard, conn)
		conn.Write([]byte("RESPONSE"))
	})
}

// TestSocksHalfCloseDeliversResponse is the regression test: SOCKS must forward
// the client's FIN to the upstream and keep relaying the response back.
func TestSocksHalfCloseDeliversResponse(t *testing.T) {
	backend := halfCloseBackend(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	socksProxy := NewSocksProxy(testSocksSettings())
	socksProxy.ValidUser = func(user, password, userAddr string) bool { return true }
	// half-close is only honored with a read timeout: once EOF has been read, TCP
	// cannot distinguish a half-close from the peer vanishing, so the surviving
	// direction must be bounded by an idle timeout
	socksProxy.Settings().ProxyReadTimeout = 15 * time.Second
	socksProxy.Settings().ProxyWriteTimeout = 30 * time.Second
	socksProxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, a string) (net.Conn, error) {
		return (&net.Dialer{}).Dial("tcp", backend)
	}
	go socksProxy.ListenAndServe(ctx, "tcp", addr)
	waitForTCP(t, addr)

	conn := socksConnect(t, addr, "half.test", 443)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("REQUEST")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("the response was dropped after the client half-closed: %v", err)
	}
	if string(buf) != "RESPONSE" {
		t.Fatalf("got %q, want RESPONSE", buf)
	}
}

// TestSocksHalfCloseNeedsReadTimeout pins the safety gate at the proxy level.
// With no read timeout, half-close is deliberately NOT honored: a client that
// merely went away is indistinguishable from one that half-closed, so honoring it
// would park the relay forever on a silent upstream. The tunnel is torn down
// instead, which is the pre-existing behavior.
func TestSocksHalfCloseNeedsReadTimeout(t *testing.T) {
	backend := halfCloseBackend(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	socksProxy := NewSocksProxy(testSocksSettings())
	socksProxy.ValidUser = func(user, password, userAddr string) bool { return true }
	// no timeouts
	socksProxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, a string) (net.Conn, error) {
		return (&net.Dialer{}).Dial("tcp", backend)
	}
	go socksProxy.ListenAndServe(ctx, "tcp", addr)
	waitForTCP(t, addr)

	conn := socksConnect(t, addr, "half.test", 443)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte("REQUEST"))
	conn.(*net.TCPConn).CloseWrite()

	// the tunnel is torn down rather than parked: the read must end promptly
	// rather than hanging until the deadline
	buf := make([]byte, 8)
	start := time.Now()
	_, err := io.ReadFull(conn, buf)
	if err == nil {
		t.Fatal("half-close was honored with no read timeout, which risks parking the relay forever")
	}
	if 4*time.Second < time.Since(start) {
		t.Fatalf("the relay parked for %s instead of tearing down", time.Since(start))
	}
}

// TestHttpConnectHalfCloseTearsDown pins that the http proxy is unchanged: it
// still treats a client FIN as end-of-tunnel. HTTP never needs half-close, and
// waiting on the upstream after a client disconnect would only delay reclaiming
// the connection.
func TestHttpConnectHalfCloseTearsDown(t *testing.T) {
	backend := halfCloseBackend(t)

	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyReadTimeout = 15 * time.Second
	proxy.Settings().ProxyWriteTimeout = 30 * time.Second
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		return (&net.Dialer{}).Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, reader := connectVia(t, proxyAddr, "half.test:443")
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte("REQUEST"))
	conn.(*net.TCPConn).CloseWrite()

	buf := make([]byte, 8)
	start := time.Now()
	if _, err := io.ReadFull(reader, buf); err == nil {
		t.Fatal("the http proxy propagated a half-close; it should tear the tunnel down")
	}
	if 4*time.Second < time.Since(start) {
		t.Fatalf("the http relay parked for %s instead of tearing down", time.Since(start))
	}
}

// TestSocksConnectUsesSharedBufferPool guards the per-connection memory cost. The
// relay must draw its buffers from the shared connect message pool (whose largest
// size class is 4kib) rather than a private pool of large buffers: a relay holds
// its buffer for the connection's whole lifetime, so the size is multiplied by
// every concurrent tunnel.
func TestSocksConnectUsesSharedBufferPool(t *testing.T) {
	backend := echoBackend(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	socksProxy := NewSocksProxy(testSocksSettings())
	socksProxy.ValidUser = func(user, password, userAddr string) bool { return true }
	socksProxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, a string) (net.Conn, error) {
		return (&net.Dialer{}).Dial("tcp", backend)
	}
	go socksProxy.ListenAndServe(ctx, "tcp", addr)
	waitForTCP(t, addr)

	taken, returned := poolCounts()

	conn := socksConnect(t, addr, "echo.test", 443)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("ping"))
	io.ReadFull(conn, make([]byte, 4))
	conn.Close()

	// the relay must have drawn from the shared pool; a private buffer pool would
	// leave these counters untouched
	settlePool(t, taken, returned, 5*time.Second)
}

// TestSocksProxyStatsAreReachableAndShared guards the observability the data path
// has left. Nothing on that path logs, so these counters are the ONLY way to see
// drops, dial failures and oversize datagrams. If they are not reachable from the
// proxy, or if each listener gets its own copy, then removing the logs did not
// trade logging for counting — it just made the proxy blind.
func TestSocksProxyStatsAreReachableAndShared(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socksProxy := NewSocksProxy(testSocksSettings())
	socksProxy.ValidUser = func(user, password, userAddr string) bool { return true }
	socksProxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, a string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	// the caller runs one listener per address family against the SAME proxy
	addr1 := freeTCPAddr(t)
	addr2 := freeTCPAddr(t)
	go socksProxy.ListenAndServe(ctx, "tcp", addr1)
	go socksProxy.ListenAndServe(ctx, "tcp", addr2)
	waitForTCP(t, addr1)
	waitForTCP(t, addr2)

	if got := socksProxy.Stats().ConnectDialErrors; got != 0 {
		t.Fatalf("ConnectDialErrors = %d before any traffic", got)
	}

	// drive a failing connect through EACH listener
	for _, addr := range []string{addr1, addr2} {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte{0x05, 0x01, 0x02})
		io.ReadFull(conn, make([]byte, 2))
		conn.Write([]byte{0x01, 0x01, 'u', 0x01, 'p'})
		io.ReadFull(conn, make([]byte, 2))
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
		io.ReadFull(conn, make([]byte, 10))
		conn.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for socksProxy.Stats().ConnectDialErrors < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := socksProxy.Stats().ConnectDialErrors; got != 2 {
		t.Fatalf("ConnectDialErrors = %d, want 2: the counters are not shared across "+
			"listeners, so the data path's only observability is split and unreadable", got)
	}
}

// TestStatsFlushIsServerPacedNotClientDriven pins the one place the data path is
// allowed to reach a log.
//
// Per-event logging is an amplification vector: a client picks how often its
// connections fail, so it picks how much the server writes. A PERIODIC flush is
// not, because the SERVER picks the rate. This asserts both halves: a client that
// drives a thousand failures produces at most a handful of log lines, and an idle
// proxy produces none at all.
func TestStatsFlushIsServerPacedNotClientDriven(t *testing.T) {
	logger := &countingConnectLogger{}

	settings := testHttpSettings()
	settings.Log = logger
	settings.StatsLogInterval = 200 * time.Millisecond
	settings.ProxyConnectTimeout = minProxyConnectTimeout

	proxy := NewHttpProxy(settings)
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	// an idle proxy must stay silent, however long it runs
	time.Sleep(700 * time.Millisecond)
	if n := logger.count(); n != 0 {
		t.Fatalf("an idle proxy emitted %d stats line(s); the flush must only emit on change", n)
	}

	// now let a client drive a large number of failures
	const failures = 200
	for i := 0; i < failures; i += 1 {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		fmt.Fprintf(conn, "CONNECT dead.test:443 HTTP/1.1\r\nHost: dead.test:443\r\n\r\n")
		time.Sleep(time.Millisecond)
		conn.Close()
	}
	time.Sleep(1 * time.Second)

	// the log volume must be bounded by the SERVER's interval, not by the client's
	// failure count
	lines := logger.count()
	if lines == 0 {
		t.Fatal("the stats flush never emitted, so the failures are unobservable")
	}
	if failures/4 < lines {
		t.Fatalf("%d client-driven failures produced %d log lines: the log volume tracks the "+
			"CLIENT's rate, which is the amplification we removed", failures, lines)
	}
	if got := proxy.Stats().ConnectDialErrors; got == 0 {
		t.Fatal("ConnectDialErrors was not counted")
	}
	t.Logf("%d client-driven failures -> %d stats lines; counters: %+v",
		failures, lines, proxy.Stats())
}

type countingConnectLogger struct {
	mu    sync.Mutex
	lines int
}

func (self *countingConnectLogger) count() int {
	self.mu.Lock()
	defer self.mu.Unlock()
	return self.lines
}

func (self *countingConnectLogger) record() {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.lines += 1
}

func (self *countingConnectLogger) Info(args ...any)                    { self.record() }
func (self *countingConnectLogger) Infof(format string, args ...any)    { self.record() }
func (self *countingConnectLogger) Warningf(format string, args ...any) { self.record() }
func (self *countingConnectLogger) Errorf(format string, args ...any)   { self.record() }
func (self *countingConnectLogger) V(level int32) connect.Verbose       { return nopVerbose{} }

type nopVerbose struct{}

func (nopVerbose) Enabled() bool                    { return false }
func (nopVerbose) Info(args ...any)                 {}
func (nopVerbose) Infof(format string, args ...any) {}
