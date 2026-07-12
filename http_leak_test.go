package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// --- shared helpers ------------------------------------------------------

// connCount tracks how many upstream conns the proxy opened vs closed, so a
// leaked upstream connection is caught even when goroutines settle.
type connCount struct {
	opened atomic.Int64
	closed atomic.Int64
}

func (self *connCount) live() int64 { return self.opened.Load() - self.closed.Load() }

type countedConn struct {
	net.Conn
	count     *connCount
	closeOnce sync.Once
}

func (self *countedConn) Close() error {
	self.closeOnce.Do(func() { self.count.closed.Add(1) })
	return self.Conn.Close()
}

// listenTCP starts a backend that serves every accepted conn with handler.
func listenTCP(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

func echoBackend(t *testing.T) string {
	return listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	})
}

// startHttpProxy runs an HttpProxy and returns its address plus a stop func that
// blocks until the server is fully down.
func startHttpProxy(t *testing.T, proxy *HttpProxy) (string, func()) {
	t.Helper()
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ListenAndServe(ctx, "tcp", addr)
	}()
	waitForTCP(t, addr)
	return addr, func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Error("http proxy did not stop")
		}
	}
}

func settleGoroutines(t *testing.T, max int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= max {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines did not settle: have %d want <= %d\n%s", n, max, buf)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func settleConns(t *testing.T, count *connCount, max int64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if count.live() <= max {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("live upstream conns = %d, want <= %d", count.live(), max)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// connectVia opens a CONNECT tunnel through the proxy and returns the conn
// positioned at the start of the tunnel payload.
func connectVia(t *testing.T, proxyAddr string, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read connect status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("connect status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read connect headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, reader
}

// --- CONNECT dial-retry termination (the never-exits leak) ---------------

// TestConnectRetryExitsWhenClientDrops is the regression test for the unbounded
// dial retry. After Hijack, net/http no longer cancels the request context when
// the client goes away, so a CONNECT to an unreachable upstream used to retry
// forever, permanently leaking the handler goroutine and the client fd — one per
// request, which a scanner can accumulate at will.
func TestConnectRetryExitsWhenClientDrops(t *testing.T) {
	var dials atomic.Int64
	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyConnectTimeout = minProxyConnectTimeout
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("connection refused")
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	runtime.GC()
	base := runtime.NumGoroutine()

	const clients = 20
	for i := 0; i < clients; i += 1 {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		fmt.Fprintf(conn, "CONNECT dead.test:443 HTTP/1.1\r\nHost: dead.test:443\r\n\r\n")
		// let the proxy hijack and enter the dial retry, then drop the client
		time.Sleep(20 * time.Millisecond)
		conn.Close()
	}

	// every handler must notice the client is gone and unwind
	settleGoroutines(t, base+4, 15*time.Second)

	// and must stop dialing: a loop still spinning would keep incrementing
	settled := dials.Load()
	time.Sleep(2 * time.Second)
	if grew := dials.Load() - settled; grew != 0 {
		t.Fatalf("proxy kept dialing after every client dropped (%d more dials): the retry loop has no exit", grew)
	}
}

// TestConnectRetrySucceedsAfterUpstreamComesUp checks the retry loop still does
// its job: it must keep retrying a failing dial for as long as the client is
// there, which is the whole point of the loop.
func TestConnectRetrySucceedsAfterUpstreamComesUp(t *testing.T) {
	backend := echoBackend(t)

	var attempts atomic.Int64
	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyConnectTimeout = minProxyConnectTimeout
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		if attempts.Add(1) < 3 {
			return nil, fmt.Errorf("connection refused")
		}
		var d net.Dialer
		return d.Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, reader := connectVia(t, proxyAddr, "slow.test:443")
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("tunnel echo = %q", buf)
	}
	if attempts.Load() < 3 {
		t.Fatalf("expected the dial to be retried, attempts = %d", attempts.Load())
	}
}

// --- pipelined client bytes ----------------------------------------------

// TestConnectPreservesPipelinedBytes covers a client that sends payload in the
// same segment as the CONNECT rather than waiting for the 200 (an optimistic TLS
// ClientHello). Those bytes land in net/http's read buffer; the hijacked conn
// never sees them, so a tunnel that reads only the raw conn drops them and the
// connection hangs.
func TestConnectPreservesPipelinedBytes(t *testing.T) {
	backend := echoBackend(t)

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// CONNECT and the first payload bytes in a single write, before reading the 200
	_, err = io.WriteString(conn,
		"CONNECT pipelined.test:443 HTTP/1.1\r\nHost: pipelined.test:443\r\n\r\nEARLY")
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("connect status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// the echo backend can only return EARLY if the proxy forwarded it
	buf := make([]byte, 5)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read echo: %v (the pipelined bytes were dropped)", err)
	}
	if string(buf) != "EARLY" {
		t.Fatalf("echo = %q, want EARLY", buf)
	}
}

// --- 101 upgrade teardown (the circular wait) ----------------------------

// silentUpgradeBackend accepts an HTTP request, replies 101, and then never
// sends another byte.
func silentUpgradeBackend(t *testing.T, count *connCount) string {
	return listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		// go silent: only closing this conn can unblock a reader parked on it
		io.Copy(io.Discard, conn)
	})
}

// TestUpgradeTeardownWhenClientDrops is the regression test for the 101-upgrade
// circular wait. net/http's upgrade body supports no deadlines, so a reader
// parked on it can only be unblocked by closing it — but the deferred Close ran
// only after the relay returned, which required that very reader to unblock.
// Every abandoned upgrade leaked two goroutines and the upstream conn forever.
func TestUpgradeTeardownWhenClientDrops(t *testing.T) {
	var count connCount
	backend := silentUpgradeBackend(t, &count)

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).Dial("tcp", backend)
		if err != nil {
			return nil, err
		}
		count.opened.Add(1)
		return &countedConn{Conn: conn, count: &count}, nil
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	runtime.GC()
	base := runtime.NumGoroutine()

	const clients = 10
	for i := 0; i < clients; i += 1 {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn,
			"GET http://upgrade.test/ws HTTP/1.1\r\nHost: upgrade.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

		reader := bufio.NewReader(conn)
		status, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read status: %v", err)
		}
		if !strings.Contains(status, "101") {
			t.Fatalf("upgrade status = %q", status)
		}
		// abandon the upgrade while the upstream is silent
		conn.Close()
	}

	// the upstream conns and their relay goroutines must all be reclaimed
	settleConns(t, &count, 0, 15*time.Second)
	settleGoroutines(t, base+6, 15*time.Second)
}

// --- request replay safety ------------------------------------------------

// TestNonIdempotentRequestIsNotReplayed covers a POST that fails AFTER it was
// fully sent (the origin accepted it, then died before responding). Replaying it
// could duplicate whatever effect it already had at the origin.
func TestNonIdempotentRequestIsNotReplayed(t *testing.T) {
	var received atomic.Int64
	backend := listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		received.Add(1)
		// accept the request, then die without responding
	})

	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyConnectTimeout = minProxyConnectTimeout
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	body := "charge=100"
	fmt.Fprintf(conn,
		"POST http://origin.test/pay HTTP/1.1\r\nHost: origin.test\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)

	// the proxy must give up rather than resend
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("origin received the POST %d times, want exactly 1: a non-idempotent request was replayed", got)
	}
}

// TestPostIsRetriedWhenDialFails checks the replay guard did not break warmup
// retries: when the dial itself fails the request never reached the origin, so
// retrying it is safe whatever the method.
func TestPostIsRetriedWhenDialFails(t *testing.T) {
	backend := listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})

	var attempts atomic.Int64
	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyConnectTimeout = minProxyConnectTimeout
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		if attempts.Add(1) < 3 {
			return nil, fmt.Errorf("connection refused")
		}
		var d net.Dialer
		return d.Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	body := "hello"
	fmt.Fprintf(conn,
		"POST http://origin.test/submit HTTP/1.1\r\nHost: origin.test\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: a POST that never reached the origin must still be retried", resp.StatusCode)
	}
}

// --- streaming ------------------------------------------------------------

// TestChunkedResponseIsFlushedIncrementally covers the dead chunked check.
// net/http moves Transfer-Encoding out of the header map into
// response.TransferEncoding, so testing the header for "chunked" never matched
// and streaming responses sat in the write buffer until the body ended.
func TestChunkedResponseIsFlushedIncrementally(t *testing.T) {
	release := make(chan struct{})
	backend := listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := http.ReadRequest(reader); err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
		io.WriteString(conn, "6\r\nfirst \r\n")
		<-release // withhold the rest until the client has seen the first chunk
		io.WriteString(conn, "6\r\nsecond\r\n0\r\n\r\n")
	})

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "GET http://stream.test/events HTTP/1.1\r\nHost: stream.test\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	// the first chunk must arrive before the body is complete
	buf := make([]byte, 6)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		close(release)
		t.Fatalf("first chunk did not arrive before the body ended: %v (the response was not flushed)", err)
	}
	if string(buf) != "first " {
		close(release)
		t.Fatalf("first chunk = %q", buf)
	}
	close(release)

	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != "second" {
		t.Fatalf("rest = %q", rest)
	}
}

// --- scale ----------------------------------------------------------------

// TestHttpProxyScaleNoLeak drives many concurrent tunnels and plain requests and
// asserts that goroutines, upstream conns, and pooled buffers all return to
// baseline. This is the shape that matters in production: tens of thousands of
// concurrent users, so a per-connection leak of any kind is fatal.
func TestHttpProxyScaleNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short")
	}
	backend := echoBackend(t)
	plain := listenTCP(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})

	var count connCount
	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyReadTimeout = 15 * time.Second
	proxy.Settings().ProxyWriteTimeout = 30 * time.Second
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		target := backend
		if r.Method != http.MethodConnect {
			target = plain
		}
		conn, err := (&net.Dialer{}).Dial("tcp", target)
		if err != nil {
			return nil, err
		}
		count.opened.Add(1)
		return &countedConn{Conn: conn, count: &count}, nil
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	tunnel := func() {
		conn, reader := connectVia(t, proxyAddr, "echo.test:443")
		defer conn.Close()
		conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		io.ReadFull(reader, buf)
	}
	request := func() {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// warm up, then take the baseline
	tunnel()
	request()
	settleConns(t, &count, 0, 5*time.Second)
	runtime.GC()
	base := runtime.NumGoroutine()
	takenBefore, returnedBefore, _ := connect.MessagePoolCounts()

	const rounds = 60
	var wg sync.WaitGroup
	for i := 0; i < rounds; i += 1 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tunnel()
		}()
		go func() {
			defer wg.Done()
			request()
		}()
	}
	wg.Wait()

	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, base+10, 20*time.Second)

	// every pooled copy buffer taken during the run must have been returned;
	// dropping one on an error path is a slow memory leak under load
	deadline := time.Now().Add(10 * time.Second)
	for {
		taken, returned, _ := connect.MessagePoolCounts()
		took := taken - takenBefore
		gave := returned - returnedBefore
		if took == gave {
			if took == 0 {
				t.Fatal("no pooled buffers were used; the test is not exercising the copy path")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pooled buffers leaked: took %d, returned %d", took, gave)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// poolCounts snapshots the shared connect message pool's take/return counters.
func poolCounts() (taken uint64, returned uint64) {
	t, r, _ := connect.MessagePoolCounts()
	return t, r
}

// settlePool asserts that buffers were drawn from the shared message pool since
// the snapshot, and that every one of them was returned. It catches both a relay
// that bypasses the pool (took == 0) and one that leaks buffers (took != gave).
func settlePool(t *testing.T, taken0 uint64, returned0 uint64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		taken, returned := poolCounts()
		took := taken - taken0
		gave := returned - returned0
		if took == gave {
			if took == 0 {
				t.Fatal("no buffers were drawn from the shared message pool: the relay is using a private pool, " +
					"so its per-connection memory cost is not bounded by the pool's size classes")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pooled buffers leaked: took %d, returned %d", took, gave)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testHttpSettings / testSocksSettings start from ZERO timeouts, not the product
// defaults. Most of these tests exist to prove that teardown works WITHOUT a
// timeout to fall back on — a leak test that is rescued by a 30s read timeout is
// not testing anything. Tests that need a timeout set one explicitly.
func testHttpSettings() *HttpProxySettings {
	settings := DefaultHttpProxySettings()
	settings.ProxyReadTimeout = 0
	settings.ProxyWriteTimeout = 0
	settings.ProxyIdleTimeout = 0
	return settings
}

func testSocksSettings() *SocksProxySettings {
	settings := DefaultSocksProxySettings()
	settings.ProxyReadTimeout = 0
	settings.ProxyWriteTimeout = 0
	return settings
}
