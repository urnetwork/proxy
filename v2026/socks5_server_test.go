package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- test infrastructure -------------------------------------------------

func allowAll(user, pass, userAddr string) bool { return true }

// connCounter tracks how many egress conns are open vs closed.
type connCounter struct {
	opened atomic.Int64
	closed atomic.Int64
}

func (c *connCounter) live() int64 { return c.opened.Load() - c.closed.Load() }

type countingConn struct {
	net.Conn
	c    *connCounter
	once sync.Once
}

func (cc *countingConn) Close() error {
	cc.once.Do(func() { cc.c.closed.Add(1) })
	return cc.Conn.Close()
}

// echoDial routes CONNECT to a TCP echo and ASSOCIATE flows to a UDP echo,
// counting every conn it hands out so tests can assert none leak.
func echoDial(tcpAddr string, udpAddr *net.UDPAddr, cc *connCounter) socksDialFunc {
	return func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var target string
		switch network {
		case "tcp":
			target = tcpAddr
		case "udp":
			target = udpAddr.String()
		default:
			return nil, fmt.Errorf("unsupported network %s", network)
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, target)
		if err != nil {
			return nil, err
		}
		cc.opened.Add(1)
		return &countingConn{Conn: c, c: cc}, nil
	}
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(buf[:n], addr)
		}
	}()
	return uc.LocalAddr().(*net.UDPAddr)
}

// startServer runs an accept loop serving each conn via ServeConn, with a
// WaitGroup so stop() blocks until every connection goroutine has exited.
func startServer(t *testing.T, s *socksServer) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.ServeConn(ctx, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() {
		cancel()
		ln.Close()
		wg.Wait()
	}
}

// --- SOCKS5 test client --------------------------------------------------

type testClient struct {
	t    *testing.T
	conn net.Conn
}

func dialClient(t *testing.T, addr string) *testClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return &testClient{t: t, conn: c}
}

func (tc *testClient) close() { tc.conn.Close() }

func (tc *testClient) mustWrite(b []byte) {
	tc.t.Helper()
	if _, err := tc.conn.Write(b); err != nil {
		tc.t.Fatalf("write: %v", err)
	}
}

func (tc *testClient) mustRead(n int) []byte {
	tc.t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(tc.conn, b); err != nil {
		tc.t.Fatalf("read %d: %v", n, err)
	}
	return b
}

func (tc *testClient) negotiateUserPass(user, pass string) {
	tc.t.Helper()
	tc.mustWrite([]byte{socksVersion, 1, methodUserPass})
	resp := tc.mustRead(2)
	if resp[0] != socksVersion || resp[1] != methodUserPass {
		tc.t.Fatalf("method select = % x", resp)
	}
	auth := []byte{userPassVersion, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	tc.mustWrite(auth)
	ar := tc.mustRead(2)
	if ar[0] != userPassVersion || ar[1] != authSuccess {
		tc.t.Fatalf("auth resp = % x", ar)
	}
}

func (tc *testClient) negotiateNoAuth() {
	tc.t.Helper()
	tc.mustWrite([]byte{socksVersion, 1, methodNoAuth})
	resp := tc.mustRead(2)
	if resp[0] != socksVersion || resp[1] != methodNoAuth {
		tc.t.Fatalf("method select = % x", resp)
	}
}

// request sends a SOCKS5 request and returns the reply code and bind address.
func (tc *testClient) request(cmd byte, dst *AddrSpec) (uint8, *AddrSpec) {
	tc.t.Helper()
	var b []byte
	b = append(b, socksVersion, cmd, 0x00)
	b = appendAddrSpec(b, dst)
	tc.mustWrite(b)
	h := tc.mustRead(3)
	if h[0] != socksVersion {
		tc.t.Fatalf("reply version %#x", h[0])
	}
	bnd, err := readAddrSpec(tc.conn)
	if err != nil {
		tc.t.Fatalf("read reply addr: %v", err)
	}
	return h[1], bnd
}

func (tc *testClient) associate() *net.UDPAddr {
	tc.t.Helper()
	rep, bnd := tc.request(cmdAssociate, &AddrSpec{IP: net.IPv4zero.To4(), Port: 0})
	if rep != repSuccess {
		tc.t.Fatalf("associate reply = %#x", rep)
	}
	// The control connection stays open; drop its handshake deadline.
	tc.conn.SetDeadline(time.Time{})
	return &net.UDPAddr{IP: bnd.IP, Port: bnd.Port}
}

func udpClient(t *testing.T) *net.UDPConn {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp client: %v", err)
	}
	t.Cleanup(func() { uc.Close() })
	return uc
}

func sendDatagram(t *testing.T, uc *net.UDPConn, to *net.UDPAddr, dst *AddrSpec, payload []byte) {
	t.Helper()
	var d []byte
	d = appendDatagramHeader(d, dst)
	d = append(d, payload...)
	if _, err := uc.WriteToUDP(d, to); err != nil {
		t.Fatalf("udp write: %v", err)
	}
}

func recvDatagram(t *testing.T, uc *net.UDPConn, timeout time.Duration) (*AddrSpec, []byte, error) {
	t.Helper()
	uc.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	_, dst, payload, err := parseDatagram(buf[:n])
	if err != nil {
		return nil, nil, err
	}
	return dst, append([]byte(nil), payload...), nil
}

// --- CONNECT correctness -------------------------------------------------

func TestConnectUserPassEcho(t *testing.T) {
	echo := startTCPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial(echo, nil, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("proxyid", "secret")
	rep, _ := tc.request(cmdConnect, &AddrSpec{FQDN: "example.test", Port: 80})
	if rep != repSuccess {
		t.Fatalf("connect reply = %#x", rep)
	}
	tc.mustWrite([]byte("ping"))
	if got := string(tc.mustRead(4)); got != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

func TestConnectNoAuth(t *testing.T) {
	echo := startTCPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial(echo, nil, &cc)} // ValidUser nil => no-auth
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateNoAuth()
	rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repSuccess {
		t.Fatalf("connect reply = %#x", rep)
	}
	tc.mustWrite([]byte("data"))
	if got := string(tc.mustRead(4)); got != "data" {
		t.Fatalf("echo = %q", got)
	}
}

func TestConnectAuthFailure(t *testing.T) {
	var cc connCounter
	s := &socksServer{
		settings: testSettings(), Dial: echoDial("", nil, &cc),
		ValidUser: func(u, p, a string) bool { return u == "good" && p == "pw" },
	}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.mustWrite([]byte{socksVersion, 1, methodUserPass})
	if resp := tc.mustRead(2); resp[1] != methodUserPass {
		t.Fatalf("method = % x", resp)
	}
	auth := []byte{userPassVersion, 3, 'b', 'a', 'd', 2, 'p', 'w'}
	tc.mustWrite(auth)
	ar := tc.mustRead(2)
	if ar[0] != userPassVersion || ar[1] != authFailure {
		t.Fatalf("expected auth failure, got % x", ar)
	}
}

func TestConnectDialErrorReplyCode(t *testing.T) {
	s := &socksServer{
		settings: testSettings(), ValidUser: allowAll,
		Dial: func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repConnectionRefused {
		t.Fatalf("reply = %#x want repConnectionRefused", rep)
	}
}

func TestUnsupportedCommandBind(t *testing.T) {
	s := &socksServer{settings: testSettings(), ValidUser: allowAll, Dial: echoDial("", nil, &connCounter{})}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	rep, _ := tc.request(cmdBind, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repCommandNotSupported {
		t.Fatalf("reply = %#x want repCommandNotSupported", rep)
	}
}

// TestListenAndServe exercises the real accept path.
func TestListenAndServe(t *testing.T) {
	echo := startTCPEcho(t)
	s := &socksServer{settings: testSettings(), Dial: echoDial(echo, nil, &connCounter{}), ValidUser: allowAll}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx, "tcp", addr) }()

	// Wait for the listener to come up.
	var tc *testClient
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			tc = &testClient{t: t, conn: c}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer tc.close()

	tc.negotiateUserPass("u", "p")
	rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
	if rep != repSuccess {
		t.Fatalf("connect reply = %#x", rep)
	}
	tc.mustWrite([]byte("okok"))
	if got := string(tc.mustRead(4)); got != "okok" {
		t.Fatalf("echo = %q", got)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}

// --- ASSOCIATE correctness ----------------------------------------------

func TestAssociateEcho(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()

	uc := udpClient(t)
	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	sendDatagram(t, uc, bnd, dst, []byte("hello"))

	gotDst, payload, err := recvDatagram(t, uc, 2*time.Second)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("payload = %q", payload)
	}
	if !gotDst.IP.Equal(dst.IP) || gotDst.Port != dst.Port {
		t.Fatalf("reply dst = %+v want %+v", gotDst, dst)
	}
}

func TestAssociateMultipleDestinations(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	for i := 1; i <= 5; i++ {
		dst := &AddrSpec{IP: net.IPv4(10, 0, 0, byte(i)).To4(), Port: 1000 + i}
		msg := fmt.Sprintf("msg-%d", i)
		sendDatagram(t, uc, bnd, dst, []byte(msg))
		gotDst, payload, err := recvDatagram(t, uc, 2*time.Second)
		if err != nil {
			t.Fatalf("dest %d recv: %v", i, err)
		}
		if string(payload) != msg {
			t.Fatalf("dest %d payload = %q", i, payload)
		}
		if !gotDst.IP.Equal(dst.IP) || gotDst.Port != dst.Port {
			t.Fatalf("dest %d reply dst = %+v", i, gotDst)
		}
	}
}

func TestAssociateDomainDestination(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{FQDN: "dns.example", Port: 53}
	sendDatagram(t, uc, bnd, dst, []byte("query"))
	gotDst, payload, err := recvDatagram(t, uc, 2*time.Second)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(payload) != "query" {
		t.Fatalf("payload = %q", payload)
	}
	if gotDst.FQDN != "dns.example" || gotDst.Port != 53 {
		t.Fatalf("reply dst = %+v want domain dns.example:53", gotDst)
	}
}

func TestAssociateDropsFragmented(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)
	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}

	// Fragmented datagram (FRAG != 0) must be dropped.
	var d []byte
	d = appendDatagramHeader(d, dst)
	d[2] = 1 // FRAG
	d = append(d, []byte("frag")...)
	if _, err := uc.WriteToUDP(d, bnd); err != nil {
		t.Fatalf("write: %v", err)
	}
	uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, _, err := parseAndRead(uc); err == nil {
		t.Fatal("expected no reply for fragmented datagram")
	}

	// A valid datagram still works: the association survived.
	sendDatagram(t, uc, bnd, dst, []byte("ok"))
	_, payload, err := recvDatagram(t, uc, 2*time.Second)
	if err != nil {
		t.Fatalf("recv after frag: %v", err)
	}
	if string(payload) != "ok" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestAssociateRejectsWrongSource(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}

	// Pin the association to client A.
	ucA := udpClient(t)
	sendDatagram(t, ucA, bnd, dst, []byte("a"))
	if _, payload, err := recvDatagram(t, ucA, 2*time.Second); err != nil || string(payload) != "a" {
		t.Fatalf("client A: payload=%q err=%v", payload, err)
	}

	// Client B (different source) must be ignored.
	ucB := udpClient(t)
	sendDatagram(t, ucB, bnd, dst, []byte("b"))
	ucB.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, _, err := parseAndRead(ucB); err == nil {
		t.Fatal("expected client B datagram to be rejected")
	}
}

// parseAndRead reads one datagram and parses it, for negative assertions.
func parseAndRead(uc *net.UDPConn) (byte, *AddrSpec, []byte, error) {
	buf := make([]byte, 65535)
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, nil, err
	}
	return parseDatagram(buf[:n])
}

// testSettings starts from ZERO read/write timeouts, not the product defaults.
// Several of these tests exist to prove teardown works WITHOUT a timeout to fall
// back on; a leak test rescued by a 30s read timeout proves nothing.
func testSettings() *SocksProxySettings {
	settings := DefaultSocksProxySettings()
	settings.ProxyReadTimeout = 0
	settings.ProxyWriteTimeout = 0
	return settings
}

func testSettingsIdle(idle time.Duration) *SocksProxySettings {
	settings := testSettings()
	settings.AssociateIdleTimeout = idle
	return settings
}

func testSettingsIdleFlows(idle time.Duration, maxFlows int) *SocksProxySettings {
	settings := testSettingsIdle(idle)
	settings.AssociateMaxFlows = maxFlows
	return settings
}
