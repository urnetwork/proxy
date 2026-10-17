package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// A black-holed upstream is the failure mode that actually bites a proxy in
// production: the TCP connection is established and stays established, but the
// peer never reads and never writes. Nothing errors, nothing EOFs — the relay
// simply parks. Every mechanism that reclaims such a connection has to be
// explicitly exercised, because none of them fire on their own.
//
// Two distinct parks matter, and they are NOT reclaimed by the same mechanism:
//
//   - parked in Read (upstream never sends): a read deadline can break this.
//   - parked in Write (upstream never reads, so its receive window closes and
//     ours fills): a read deadline CANNOT break this. Only a write deadline or a
//     Close can. This is the one that used to leak the goroutine and both fds
//     forever, because the deferred Close ran only after the relay returned.

// openFds counts the process's open file descriptors. A connection leak shows up
// here even when goroutine counts look fine — e.g. a conn whose owner returned
// without closing it.
func openFds(t *testing.T) int {
	t.Helper()
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		dirFile, err := os.Open(dir)
		if err != nil {
			continue
		}
		// Readdirnames, not ReadDir: ReadDir stats every entry, and on darwin the
		// /dev/fd entries go stale mid-scan, which fails the whole call.
		names, err := dirFile.Readdirnames(-1)
		dirFile.Close()
		if err != nil {
			continue
		}
		// the scan's own fd is counted here and in the baseline, so it cancels out
		return len(names)
	}
	t.Skip("cannot enumerate file descriptors on this platform")
	return 0
}

func settleFds(t *testing.T, max int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		runtime.GC()
		n := openFds(t)
		if n <= max {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("file descriptors were not reclaimed: have %d, want <= %d", n, max)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// blackHoleBackend accepts connections and then does nothing at all with them:
// it never reads and never writes, and it holds the conn open. held is closed
// only when the test tears the backend down.
func blackHoleBackend(t *testing.T) (addr string, live func() int) {
	t.Helper()
	var mu sync.Mutex
	conns := []net.Conn{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			// deliberately no Read and no Write: the peer is a black hole
		}
	}()
	return ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(conns)
	}
}

// blackHoleProxy wires an HttpProxy to a black-holed upstream, counting the
// upstream conns it hands out so a leak is visible.
func blackHoleProxy(t *testing.T, count *connCount, readTimeout, writeTimeout time.Duration) (string, func()) {
	t.Helper()
	backend, _ := blackHoleBackend(t)

	proxy := NewHttpProxy(testHttpSettings())
	proxy.Settings().ProxyReadTimeout = readTimeout
	proxy.Settings().ProxyWriteTimeout = writeTimeout
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).Dial("tcp", backend)
		if err != nil {
			return nil, err
		}
		count.opened.Add(1)
		return &countedConn{Conn: conn, count: count}, nil
	}
	return startHttpProxy(t, proxy)
}

// blastUntilBlocked writes to conn until it can no longer make progress, which
// happens once the proxy's own write to the black-holed upstream parks and the
// backpressure reaches all the way back to us. It returns when the writes stall.
func blastUntilBlocked(conn net.Conn) {
	payload := make([]byte, 256*1024)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 64; i += 1 {
		if _, err := conn.Write(payload); err != nil {
			return // our own write blocked: the pipe is full end to end
		}
	}
}

// TestConnectBlackHoleUpstreamParkedInWriteReclaimedOnShutdown is the sharpest
// version of the leak. The upstream never reads, so the relay parks in Write; no
// timeouts are configured, so no deadline will ever fire; and the client is still
// connected, so nothing on that side errors either. The ONLY thing that can
// reclaim this is shutdown closing the endpoints — which is exactly what the old
// read-deadline-only cancellation could not do.
func TestConnectBlackHoleUpstreamParkedInWriteReclaimedOnShutdown(t *testing.T) {
	var count connCount
	// no read timeout, no write timeout: nothing self-heals
	proxyAddr, stop := blackHoleProxy(t, &count, 0, 0)

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseFds := openFds(t)

	const clients = 8
	conns := []net.Conn{}
	for i := 0; i < clients; i += 1 {
		conn, reader := connectVia(t, proxyAddr, "blackhole.test:443")
		conns = append(conns, conn)
		_ = reader
		conn.SetDeadline(time.Time{})
		go blastUntilBlocked(conn)
	}
	// let every relay park in Write against the closed receive window
	time.Sleep(1 * time.Second)

	if count.live() != clients {
		t.Fatalf("live upstream conns = %d, want %d", count.live(), clients)
	}

	// shut the proxy down. Server.Close does not touch hijacked conns, so this
	// only works because the request contexts descend from the server's run ctx
	// and the relay closes its endpoints on cancellation.
	stop()

	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, baseGoroutines+6, 20*time.Second)

	for _, conn := range conns {
		conn.Close()
	}
	settleFds(t, baseFds+clients+4, 20*time.Second)
}

// TestConnectBlackHoleUpstreamParkedInReadReclaimedOnShutdown is the milder park:
// the upstream is silent but drains, so the relay sits in Read. It must be
// reclaimed on shutdown too, with no timeouts configured.
func TestConnectBlackHoleUpstreamParkedInReadReclaimedOnShutdown(t *testing.T) {
	var count connCount

	// this backend drains but never replies, so the relay parks in Read
	backend := listenTCP(t, func(conn net.Conn) {
		io.Copy(io.Discard, conn)
	})
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

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseFds := openFds(t)

	const clients = 8
	conns := []net.Conn{}
	for i := 0; i < clients; i += 1 {
		conn, _ := connectVia(t, proxyAddr, "silent.test:443")
		conn.SetDeadline(time.Time{})
		conn.Write([]byte("hello"))
		conns = append(conns, conn)
	}
	time.Sleep(500 * time.Millisecond)

	if count.live() != clients {
		t.Fatalf("live upstream conns = %d, want %d", count.live(), clients)
	}

	stop()

	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, baseGoroutines+6, 20*time.Second)

	for _, conn := range conns {
		conn.Close()
	}
	settleFds(t, baseFds+clients+4, 20*time.Second)
}

// TestConnectBlackHoleUpstreamReclaimedByTimeouts is the production configuration
// (read and write timeouts are both set): a black-holed upstream must be reclaimed
// on its own, without a shutdown and without the client doing anything, so that a
// steady trickle of black-holed tunnels cannot accumulate fds indefinitely.
func TestConnectBlackHoleUpstreamReclaimedByTimeouts(t *testing.T) {
	var count connCount
	proxyAddr, stop := blackHoleProxy(t, &count, 500*time.Millisecond, 500*time.Millisecond)
	defer stop()

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseFds := openFds(t)

	const clients = 8
	conns := []net.Conn{}
	for i := 0; i < clients; i += 1 {
		conn, _ := connectVia(t, proxyAddr, "blackhole.test:443")
		conns = append(conns, conn)
		conn.SetDeadline(time.Time{})
		go blastUntilBlocked(conn)
	}

	// with no data ever flowing back, the read timeout expires and the relay must
	// tear itself down and release both endpoints — no client action, no shutdown
	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, baseGoroutines+6, 20*time.Second)

	for _, conn := range conns {
		conn.Close()
	}
	settleFds(t, baseFds+clients+4, 20*time.Second)
}

// TestConnectBlackHoleUpstreamReclaimedWhenClientDrops covers the common shape: a
// client gives up on a tunnel whose upstream never answered. The relay is parked
// reading the silent upstream; the client's disconnect must tear it down.
func TestConnectBlackHoleUpstreamReclaimedWhenClientDrops(t *testing.T) {
	var count connCount

	backend := listenTCP(t, func(conn net.Conn) {
		io.Copy(io.Discard, conn) // drains, never replies
	})
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
	baseGoroutines := runtime.NumGoroutine()
	baseFds := openFds(t)

	const clients = 10
	for i := 0; i < clients; i += 1 {
		conn, _ := connectVia(t, proxyAddr, "silent.test:443")
		conn.Close() // give up on the tunnel
	}

	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, baseGoroutines+6, 20*time.Second)
	settleFds(t, baseFds+4, 20*time.Second)
}

// TestUpgradeBlackHoleUpstreamReclaimedOnShutdown is the 101-upgrade equivalent:
// the upgrade body has no deadline support at all, so neither a read nor a write
// deadline can reach it. Shutdown must still reclaim it, which is only possible
// because the relay closes its endpoints.
func TestUpgradeBlackHoleUpstreamReclaimedOnShutdown(t *testing.T) {
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

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseFds := openFds(t)

	const clients = 8
	conns := []net.Conn{}
	for i := 0; i < clients; i += 1 {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn,
			"GET http://upgrade.test/ws HTTP/1.1\r\nHost: upgrade.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		reader := bufio.NewReader(conn)
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("read status: %v", err)
		}
		conn.SetDeadline(time.Time{})
		conns = append(conns, conn)
	}
	time.Sleep(500 * time.Millisecond)

	// hold the clients open: only shutdown can reclaim these
	stop()

	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, baseGoroutines+6, 20*time.Second)

	for _, conn := range conns {
		conn.Close()
	}
	settleFds(t, baseFds+clients+4, 20*time.Second)
}

// TestSocksBlackHoleUpstreamReclaimedOnShutdown gives the SOCKS CONNECT path the
// same treatment: a black-holed upstream with no timeouts, reclaimed only because
// shutdown closes the relay's endpoints.
func TestSocksBlackHoleUpstreamReclaimedOnShutdown(t *testing.T) {
	backendAddr, _ := blackHoleBackend(t)

	var count connCount
	ctx, cancel := context.WithCancel(context.Background())
	addr := freeTCPAddr(t)
	socksProxy := NewSocksProxy(testSocksSettings())
	socksProxy.ValidUser = func(user, password, userAddr string) bool { return true }
	socksProxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).Dial("tcp", backendAddr)
		if err != nil {
			return nil, err
		}
		count.opened.Add(1)
		return &countedConn{Conn: conn, count: &count}, nil
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- socksProxy.ListenAndServe(ctx, "tcp", addr)
	}()
	waitForTCP(t, addr)

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseFds := openFds(t)

	const clients = 8
	conns := []net.Conn{}
	for i := 0; i < clients; i += 1 {
		conn := socksConnect(t, addr, "blackhole.test", 443)
		conns = append(conns, conn)
		conn.SetDeadline(time.Time{})
		go blastUntilBlocked(conn)
	}
	time.Sleep(1 * time.Second)

	if count.live() != clients {
		t.Fatalf("live upstream conns = %d, want %d", count.live(), clients)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("socks proxy did not stop")
	}

	settleConns(t, &count, 0, 20*time.Second)
	settleGoroutines(t, baseGoroutines+6, 20*time.Second)

	for _, conn := range conns {
		conn.Close()
	}
	settleFds(t, baseFds+clients+4, 20*time.Second)
}
