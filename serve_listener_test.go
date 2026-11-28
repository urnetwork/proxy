// Serve runs a proxy on a listener its caller bound, for a caller that picks
// the address or screens connections itself. These tests prove the proxy takes
// its connections from that listener and owns it from the call, like
// ListenAndServe owns the listener it binds.
package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Counts the connections the proxy accepted from this listener.
type acceptCountingListener struct {
	net.Listener
	acceptedCount atomic.Int64
}

func (self *acceptCountingListener) Accept() (net.Conn, error) {
	conn, err := self.Listener.Accept()
	if err == nil {
		self.acceptedCount.Add(1)
	}
	return conn, err
}

func newAcceptCountingListener(t *testing.T) *acceptCountingListener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
	})
	return &acceptCountingListener{Listener: l}
}

func pingPongBackend(t *testing.T) string {
	t.Helper()
	return startTCPBackend(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
			return
		}
		_, _ = conn.Write([]byte("pong"))
	})
}

func expectPong(t *testing.T, conn net.Conn, reader io.Reader) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(reader, pong); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(pong) != "pong" {
		t.Fatalf("tunnel read %q, want pong", pong)
	}
}

// After the serving scope ends, the caller's listener is closed.
func expectListenerClosed(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("the served listener at %s still accepts after the serving context ended", addr)
	}
}

func TestHttpProxyServeUsesCallerListener(t *testing.T) {
	backendAddr := pingPongBackend(t)

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", backendAddr)
	}

	l := newAcceptCountingListener(t)
	proxyAddr := l.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- proxy.Serve(ctx, l)
	}()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read connect status: %v", err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("connect status = %q, want 200", status)
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
	expectPong(t, conn, reader)

	if accepted := l.acceptedCount.Load(); accepted != 1 {
		t.Fatalf("the caller's listener accepted %d connections, want 1", accepted)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after its context ended, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context ended")
	}
	expectListenerClosed(t, proxyAddr)
}

// A drain closes a served listener as it closes a bound one, and Serve keeps
// the established work until the context ends.
func TestHttpProxyDrainClosesServedListener(t *testing.T) {
	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
		return nil, NewConnectRefusal(ConnectRefusalReset, io.EOF)
	}

	l := newAcceptCountingListener(t)
	proxyAddr := l.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- proxy.Serve(ctx, l)
	}()
	// one accepted connection proves the listener is registered and serving
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.Close()

	proxy.Drain()
	expectListenerClosed(t, proxyAddr)
	select {
	case err := <-served:
		t.Fatalf("Serve returned %v during the drain, before its context ended", err)
	default:
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after its context ended, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context ended")
	}
}

func TestSocksProxyServeUsesCallerListener(t *testing.T) {
	backendAddr := pingPongBackend(t)

	proxy := NewSocksProxy(testSocksSettings())
	proxy.ValidUser = func(user string, password string, userAddr string) bool {
		return user == "u" && password == "p"
	}
	proxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", backendAddr)
	}

	l := newAcceptCountingListener(t)
	proxyAddr := l.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- proxy.Serve(ctx, l)
	}()

	conn := socksConnect(t, proxyAddr, "example.test", 443)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	expectPong(t, conn, conn)

	if accepted := l.acceptedCount.Load(); accepted != 1 {
		t.Fatalf("the caller's listener accepted %d connections, want 1", accepted)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after its context ended, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context ended")
	}
	expectListenerClosed(t, proxyAddr)

	// the stats flusher Serve started is joined like ListenAndServe's
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := proxy.WaitStats(waitCtx); err != nil {
		t.Fatalf("WaitStats after Serve: %v", err)
	}
}
