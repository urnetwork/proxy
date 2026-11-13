package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSocksProxyPreservesFQDNForRemoteDial(t *testing.T) {
	backendAddr := startTCPBackend(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("backend read: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("backend got %q, want ping", string(buf))
			return
		}
		_, _ = conn.Write([]byte("pong"))
	})

	dialed := make(chan string, 1)
	proxyAddr, stop := startSocksProxy(t, func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		dialed <- addr
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backendAddr)
	})
	defer stop()

	conn := socksConnect(t, proxyAddr, "example.test", 443)
	defer conn.Close()

	select {
	case got := <-dialed:
		if got != "example.test:443" {
			t.Fatalf("dial addr = %q, want example.test:443", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not dial")
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q, want pong", string(buf))
	}
}

func TestSocksProxyClosesClientWhenUpstreamCloses(t *testing.T) {
	backendAddr := startTCPBackend(t, func(conn net.Conn) {
		_ = conn.Close()
	})

	proxyAddr, stop := startSocksProxy(t, func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backendAddr)
	})
	defer stop()

	conn := socksConnect(t, proxyAddr, "example.test", 443)
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("read succeeded after upstream closed")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("client read timed out; proxy did not close client connection")
	}
}

// --- read-only accessors do not build/freeze the server ------------------

// TestSocksProxyStatsBeforeServerBuiltReturnsZeroValue guards Stats' new
// contract: before anything has built the server, Stats must return the zero
// value rather than building it just to read counters.
func TestSocksProxyStatsBeforeServerBuiltReturnsZeroValue(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())

	if got := proxy.Stats(); got != (SocksStatsSnapshot{}) {
		t.Fatalf("Stats before build = %+v, want zero value", got)
	}
}

// TestSocksProxyActiveCountBeforeServerBuiltReturnsZero mirrors the Stats
// case for ActiveCount.
func TestSocksProxyActiveCountBeforeServerBuiltReturnsZero(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())

	if got := proxy.ActiveCount(); got != 0 {
		t.Fatalf("ActiveCount before build = %d, want 0", got)
	}
}

// TestSocksProxyReadOnlyAccessorsDoNotFreezeConfiguration is the regression
// test for the bug this PR fixes: Stats/ActiveCount used to call ensureServer,
// which freezes Settings()/ValidUser/ConnectDialWithRequest at whatever they
// were when first read. That meant merely observing a counter before serving
// started could silently lock in stale configuration. This test reads both
// accessors first, confirms they did not build the server, THEN sets
// ValidUser, and proves the late-set ValidUser still takes effect once
// serving actually starts.
func TestSocksProxyReadOnlyAccessorsDoNotFreezeConfiguration(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())

	if s := proxy.builtServer(); s != nil {
		t.Fatal("server built before any use")
	}
	if got := proxy.Stats(); got != (SocksStatsSnapshot{}) {
		t.Fatalf("Stats before build = %+v, want zero value", got)
	}
	if got := proxy.ActiveCount(); got != 0 {
		t.Fatalf("ActiveCount before build = %d, want 0", got)
	}
	if s := proxy.builtServer(); s != nil {
		t.Fatal("Stats/ActiveCount must not build the server")
	}

	// configure ValidUser only AFTER the read-only accessors above ran
	const user, pass = "lateuser", "latepass"
	proxy.ValidUser = func(u, p, addr string) bool { return u == user && p == pass }
	echo := startTCPEcho(t)
	proxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echo)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.ListenAndServe(ctx, "tcp", addr) }()
	waitForTCP(t, addr)

	if s := proxy.builtServer(); s == nil {
		t.Fatal("server must be built once serving starts")
	}

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass(user, pass)
	rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repSuccess {
		t.Fatalf("connect reply = %#x, want success: ValidUser set after the "+
			"read-only accessors did not take effect", rep)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

// --- newServer: nil ValidUser preserves no-auth ---------------------------

func TestNewServerNilValidUserLeavesServerValidUserNil(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())
	// ValidUser left nil deliberately

	server := proxy.newServer()

	if server.ValidUser != nil {
		t.Fatal("server.ValidUser must be nil when SocksProxy.ValidUser is nil, to preserve no-auth")
	}
}

func TestNewServerNonNilValidUserDelegatesToConfiguredCallback(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())
	proxy.ValidUser = func(user, password, userAddr string) bool {
		return user == "alice" && password == "secret"
	}

	server := proxy.newServer()

	if server.ValidUser == nil {
		t.Fatal("server.ValidUser must be set when SocksProxy.ValidUser is non-nil")
	}
	if !server.ValidUser("alice", "secret", "1.2.3.4") {
		t.Fatal("server.ValidUser must accept the configured credentials")
	}
	if server.ValidUser("bob", "wrong", "1.2.3.4") {
		t.Fatal("server.ValidUser must reject credentials the callback rejects")
	}
}

// TestNewServerValidUserPanicRecoversToFalse guards the connect.HandleError1
// wrapping: a panicking ValidUser must not crash the server, and must be
// treated as a rejected login.
func TestNewServerValidUserPanicRecoversToFalse(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())
	proxy.ValidUser = func(user, password, userAddr string) bool {
		panic("boom")
	}

	server := proxy.newServer()

	if got := server.ValidUser("u", "p", "addr"); got {
		t.Fatal("server.ValidUser must return false when the callback panics, not propagate the panic")
	}
}

// --- end-to-end through the public SocksProxy API -------------------------

// TestSocksProxyNilValidUserAllowsNoAuthEndToEnd exercises the nil-ValidUser
// path through the real SocksProxy wiring (not the raw socksServer), matching
// how socks/main.go's dev tool now relies on the library default instead of
// its own "accept everything" override.
func TestSocksProxyNilValidUserAllowsNoAuthEndToEnd(t *testing.T) {
	echo := startTCPEcho(t)

	proxy := NewSocksProxy(testSocksSettings())
	// ValidUser left nil deliberately: no-auth must be offered and accepted.
	proxy.ConnectDialWithRequest = func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echo)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.ListenAndServe(ctx, "tcp", addr) }()
	waitForTCP(t, addr)

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateNoAuth()
	rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repSuccess {
		t.Fatalf("connect reply = %#x, want success", rep)
	}
	tc.mustWrite([]byte("ping"))
	if got := string(tc.mustRead(4)); got != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

// TestSocksProxyValidUserPanicRecoversAsAuthFailureEndToEnd is the negative
// counterpart: a panicking ValidUser, wired through the real SocksProxy, must
// surface to the wire as an ordinary auth failure rather than taking down the
// connection or the server.
func TestSocksProxyValidUserPanicRecoversAsAuthFailureEndToEnd(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())
	proxy.ValidUser = func(user, password, userAddr string) bool {
		panic("boom")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.ListenAndServe(ctx, "tcp", addr) }()
	waitForTCP(t, addr)

	tc := dialClient(t, addr)
	defer tc.close()
	tc.mustWrite([]byte{socksVersion, 1, methodUserPass})
	if resp := tc.mustRead(2); resp[0] != socksVersion || resp[1] != methodUserPass {
		t.Fatalf("method select = % x", resp)
	}
	auth := []byte{userPassVersion, 1, 'u', 1, 'p'}
	tc.mustWrite(auth)
	ar := tc.mustRead(2)
	if ar[0] != userPassVersion || ar[1] != authFailure {
		t.Fatalf("auth resp = % x, want auth failure: panic must not crash the connection", ar)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

// TestSocksProxyNoAuthClientRejectedWhenValidUserSet pins the auth side of
// the negotiation: when ValidUser is set, a client offering only no-auth
// (method 0x00) must be rejected with no-acceptable-methods (0xff) rather
// than silently relayed.
func TestSocksProxyNoAuthClientRejectedWhenValidUserSet(t *testing.T) {
	proxy := NewSocksProxy(testSocksSettings())
	proxy.ValidUser = func(user, password, userAddr string) bool {
		return true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() { errCh <- proxy.ListenAndServe(ctx, "tcp", addr) }()
	waitForTCP(t, addr)

	tc := dialClient(t, addr)
	defer tc.close()
	tc.mustWrite([]byte{socksVersion, 1, methodNoAuth})
	if resp := tc.mustRead(2); resp[0] != socksVersion || resp[1] != methodNoAcceptable {
		t.Fatalf("method select = % x, want no-acceptable-methods (0xff)", resp)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

func startSocksProxy(t *testing.T, dial func(context.Context, SocksRequest, string, string) (net.Conn, error)) (string, func()) {
	t.Helper()

	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	proxy := NewSocksProxy(testSocksSettings())
	proxy.ValidUser = func(user string, password string, userAddr string) bool {
		return true
	}
	proxy.ConnectDialWithRequest = dial

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ListenAndServe(ctx, "tcp", addr)
	}()
	waitForTCP(t, addr)

	stop := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !strings.Contains(err.Error(), "closed network connection") {
				t.Fatalf("socks proxy returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("socks proxy did not stop")
		}
	}
	return addr, stop
}

func socksConnect(t *testing.T, proxyAddr string, host string, port uint16) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks proxy: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write methods: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method: %v", err)
	}
	if method[0] != 0x05 || method[1] != 0x02 {
		t.Fatalf("method response = %v, want [5 2]", method)
	}

	auth := []byte{0x01, 0x01, 'u', 0x01, 'p'}
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth: %v", err)
	}
	if authResp[0] != 0x01 || authResp[1] != 0x00 {
		t.Fatalf("auth response = %v, want [1 0]", authResp)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if replyHeader[0] != 0x05 || replyHeader[1] != 0x00 {
		t.Fatalf("connect reply = %v, want success", replyHeader)
	}
	switch replyHeader[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(length[0])+2))
		}
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	default:
		t.Fatalf("unexpected reply address type %d", replyHeader[3])
	}
	if err != nil {
		t.Fatalf("read connect reply address: %v", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	return conn
}

func startTCPBackend(t *testing.T, handler func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
	})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
	}()

	return ln.Addr().String()
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close tcp addr reservation: %v", err)
	}
	return addr
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tcp addr %s did not become ready: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustPort(t *testing.T, addr string) uint16 {
	t.Helper()

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return uint16(port)
}
