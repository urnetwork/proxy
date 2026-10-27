package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- drainState unit behavior --------------------------------------------

func TestDrainStateZeroValue(t *testing.T) {
	var d drainState

	if d.Draining() {
		t.Fatal("zero value must not be draining")
	}
	if !d.tryEnter() {
		t.Fatal("tryEnter before drain was refused")
	}
	if got := d.ActiveCount(); got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}

	// WaitIdle requires BOTH draining and idle
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer waitCancel()
	if d.WaitIdle(waitCtx) {
		t.Fatal("WaitIdle must not report idle before a drain begins")
	}

	d.Drain()
	if !d.Draining() {
		t.Fatal("Draining after Drain")
	}
	if d.tryEnter() {
		t.Fatal("tryEnter after drain must be refused atomically")
	}

	idleCh := make(chan bool, 1)
	go func() {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer waitCancel()
		idleCh <- d.WaitIdle(waitCtx)
	}()
	d.exit()
	select {
	case idle := <-idleCh:
		if !idle {
			t.Fatal("WaitIdle must report idle after the last exit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitIdle did not observe the last exit")
	}

	// a listener registered after the drain began is closed immediately
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if d.registerListener(l) {
		t.Fatal("registerListener must refuse after a drain began")
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("listener must be closed after refused registration")
	}
}

// --- http drain ----------------------------------------------------------

// TestHttpProxyDrainKeepsTunnelRefusesNew models the deploy drain
// (PROXYDRAIN1.md §3.2): after Drain, the in-flight CONNECT tunnel keeps
// relaying, new connections are refused at accept, and WaitIdle observes the
// tunnel ending.
func TestHttpProxyDrainKeepsTunnelRefusesNew(t *testing.T) {
	backendAddr := startTCPBackend(t, func(conn net.Conn) {
		defer conn.Close()
		// echo until the client closes
		io.Copy(conn, conn)
	})

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(r.Context(), "tcp", backendAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ListenAndServe(ctx, "tcp", proxyAddr)
	}()
	waitForTCP(t, proxyAddr)

	// establish a CONNECT tunnel
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("connect status = %q err=%v", status, err)
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
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel echo = %q err=%v", string(buf), err)
	}

	proxy.Drain()

	// new connections are refused (listener closed)
	if c, err := net.DialTimeout("tcp", proxyAddr, 500*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("dial after drain must fail")
	}

	// the in-flight tunnel keeps relaying
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("write tunnel after drain: %v", err)
	}
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("tunnel echo after drain = %q err=%v", string(buf), err)
	}
	if got := proxy.ActiveCount(); got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}

	// ending the tunnel is observed by WaitIdle
	idleCh := make(chan bool, 1)
	go func() {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer waitCancel()
		idleCh <- proxy.WaitIdle(waitCtx)
	}()
	conn.Close()
	select {
	case idle := <-idleCh:
		if !idle {
			t.Fatal("WaitIdle must observe the tunnel ending")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitIdle did not return")
	}

	// ListenAndServe holds runCtx (and so the in-flight tunnels) through the
	// drain and returns nil only when the caller cancels: the hard teardown
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe after cancel = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

// TestHttpProxyDrainRefusesKeptAliveRequests covers the request-layer gate: a
// request pipelined on a kept-alive connection after the drain began gets a
// 503 with Connection: close, while the accept side is already closed.
func TestHttpProxyDrainRefusesKeptAliveRequests(t *testing.T) {
	backend := startTCPBackend(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			body := "ok"
			resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n" + body
			if _, err := io.WriteString(conn, resp); err != nil {
				return
			}
		}
	})

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(r.Context(), "tcp", backend)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ListenAndServe(ctx, "tcp", proxyAddr)
	}()
	waitForTCP(t, proxyAddr)

	proxyUrl := &url.URL{Scheme: "http", Host: proxyAddr}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			// keep-alive on: the second request must reuse the pooled conn,
			// because the listener is closed by then
			DisableKeepAlives: false,
		},
		Timeout: 5 * time.Second,
	}

	response, err := client.Get("http://origin.test/one")
	if err != nil {
		t.Fatalf("request before drain: %v", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status before drain = %d", response.StatusCode)
	}

	proxy.Drain()

	response, err = client.Get("http://origin.test/two")
	if err != nil {
		t.Fatalf("request during drain: %v", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status during drain = %d, want 503", response.StatusCode)
	}
	if !response.Close && !strings.EqualFold(response.Header.Get("Connection"), "close") {
		t.Fatalf("draining response must carry Connection: close")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe after cancel = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

// TestHttpProxyServeAfterDrainReturnsNil covers the register-after-drain
// path: a ListenAndServe that starts after the drain began serves nothing
// and returns nil.
func TestHttpProxyServeAfterDrainReturnsNil(t *testing.T) {
	proxy := NewHttpProxy(testHttpSettings())
	proxy.Drain()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := proxy.ListenAndServe(ctx, "tcp", freeTCPAddr(t)); err != nil {
		t.Fatalf("ListenAndServe after drain = %v, want nil", err)
	}
}

// --- socks drain ---------------------------------------------------------

// TestSocksProxyDrainKeepsRelayRefusesNew mirrors the http drain test for the
// socks path: the in-flight CONNECT relay keeps working after Drain, new
// connections are refused, and WaitIdle observes the relay ending.
func TestSocksProxyDrainKeepsRelayRefusesNew(t *testing.T) {
	echo := startTCPEcho(t)

	socksProxy := NewSocksProxy(testSocksSettings())
	socksProxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echo)
	}
	socksProxy.ValidUser = allowAll

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- socksProxy.ListenAndServe(ctx, "tcp", addr)
	}()
	waitForTCP(t, addr)

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	tc := &testClient{t: t, conn: c}
	defer tc.close()

	tc.negotiateUserPass("u", "p")
	rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repSuccess {
		t.Fatalf("connect reply = %#x", rep)
	}
	tc.mustWrite([]byte("ping"))
	if got := string(tc.mustRead(4)); got != "ping" {
		t.Fatalf("echo = %q", got)
	}

	socksProxy.Drain()

	// new connections are refused (listener closed)
	if c2, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		c2.Close()
		t.Fatal("dial after drain must fail")
	}

	// the in-flight relay keeps working
	tc.mustWrite([]byte("pong"))
	if got := string(tc.mustRead(4)); got != "pong" {
		t.Fatalf("echo after drain = %q", got)
	}
	if got := socksProxy.ActiveCount(); got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}

	idleCh := make(chan bool, 1)
	go func() {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer waitCancel()
		idleCh <- socksProxy.WaitIdle(waitCtx)
	}()
	tc.close()
	select {
	case idle := <-idleCh:
		if !idle {
			t.Fatal("WaitIdle must observe the relay ending")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitIdle did not return")
	}

	// ListenAndServe holds runCtx through the drain and returns nil only on
	// the caller's cancel: the hard teardown
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe after cancel = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}
