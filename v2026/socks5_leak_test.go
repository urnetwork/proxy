package proxy

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// waitGoroutines waits until the live goroutine count drops to max, dumping all
// stacks on failure so a leak is diagnosable.
func waitGoroutines(t *testing.T, max int, d time.Duration) {
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

func waitConns(t *testing.T, cc *connCounter, max int64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cc.live() <= max {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("live egress conns = %d want <= %d", cc.live(), max)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runAssociation opens a control connection, associates, exchanges one datagram
// with each of `dests` distinct destinations, then closes the control
// connection (which must tear the whole association down).
func runAssociation(t *testing.T, addr string, dests int) {
	t.Helper()
	tc := dialClient(t, addr)
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()

	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Errorf("udp client: %v", err)
		tc.close()
		return
	}
	defer uc.Close()

	for i := 0; i < dests; i++ {
		dst := &AddrSpec{IP: net.IPv4(172, 16, byte(i>>8), byte(i)).To4(), Port: 2000 + i}
		payload := []byte(fmt.Sprintf("d%d", i))
		sendDatagram(t, uc, bnd, dst, payload)
		// Best-effort read of the echo to drive the reply path.
		recvDatagram(t, uc, 500*time.Millisecond)
	}
	tc.close()
}

func TestConnectNoLeak(t *testing.T) {
	echo := startTCPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettings(), Dial: echoDial(echo, nil, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	oneConnect := func() {
		tc := dialClient(t, addr)
		tc.negotiateUserPass("u", "p")
		rep, _ := tc.request(cmdConnect, &AddrSpec{IP: net.IPv4(1, 2, 3, 4).To4(), Port: 80})
		if rep != repSuccess {
			t.Errorf("connect reply %#x", rep)
		}
		tc.mustWrite([]byte("ping"))
		tc.mustRead(4)
		tc.close()
	}

	oneConnect() // warmup
	waitConns(t, &cc, 0, 2*time.Second)
	runtime.GC()
	base := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		oneConnect()
	}
	waitConns(t, &cc, 0, 5*time.Second)
	waitGoroutines(t, base+8, 5*time.Second)
}

func TestAssociateTeardownReclaims(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettingsIdle(30 * time.Second), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	const dests = 6
	for i := 0; i < dests; i++ {
		dst := &AddrSpec{IP: net.IPv4(10, 0, 0, byte(i+1)).To4(), Port: 5000 + i}
		sendDatagram(t, uc, bnd, dst, []byte("x"))
		if _, _, err := recvDatagram(t, uc, 2*time.Second); err != nil {
			t.Fatalf("dest %d: %v", i, err)
		}
	}
	if cc.live() != dests {
		t.Fatalf("live flows = %d want %d", cc.live(), dests)
	}

	// Closing the control connection must reclaim every flow.
	tc.close()
	waitConns(t, &cc, 0, 3*time.Second)
}

func TestAssociateIdleEviction(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettingsIdle(200 * time.Millisecond), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)
	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}

	sendDatagram(t, uc, bnd, dst, []byte("ping"))
	if _, payload, err := recvDatagram(t, uc, 2*time.Second); err != nil || string(payload) != "ping" {
		t.Fatalf("first echo: payload=%q err=%v", payload, err)
	}
	if cc.live() != 1 {
		t.Fatalf("live flows = %d want 1", cc.live())
	}

	// After the idle timeout, the flow is reclaimed but the association stays up.
	waitConns(t, &cc, 0, 2*time.Second)

	// A new datagram re-creates the flow and still works.
	sendDatagram(t, uc, bnd, dst, []byte("pong"))
	if _, payload, err := recvDatagram(t, uc, 2*time.Second); err != nil || string(payload) != "pong" {
		t.Fatalf("second echo: payload=%q err=%v", payload, err)
	}
	if cc.opened.Load() < 2 {
		t.Fatalf("expected flow to be re-created, opened=%d", cc.opened.Load())
	}
}

func TestAssociateMaxFlowsCap(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter
	const cap = 4
	s := &socksServer{settings: testSettingsIdleFlows(30*time.Second, cap), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	// Send to 20 distinct destinations; the table must never exceed the cap.
	for i := 0; i < 20; i++ {
		dst := &AddrSpec{IP: net.IPv4(10, 1, 0, byte(i+1)).To4(), Port: 6000 + i}
		sendDatagram(t, uc, bnd, dst, []byte("x"))
		recvDatagram(t, uc, 300*time.Millisecond) // best effort
		if live := cc.live(); live > cap {
			t.Fatalf("live flows = %d exceeds cap %d", live, cap)
		}
	}

	// Association still works after churn.
	dst := &AddrSpec{IP: net.IPv4(10, 2, 0, 1).To4(), Port: 7000}
	sendDatagram(t, uc, bnd, dst, []byte("final"))
	if _, payload, err := recvDatagram(t, uc, 2*time.Second); err != nil || string(payload) != "final" {
		t.Fatalf("final echo: payload=%q err=%v", payload, err)
	}
	if live := cc.live(); live > cap {
		t.Fatalf("final live flows = %d exceeds cap %d", live, cap)
	}

	tc.close()
	waitConns(t, &cc, 0, 3*time.Second)
}

// TestAssociateScaleNoLeak runs many concurrent associations, each fanning out
// to many destinations, and asserts every goroutine and egress conn is
// reclaimed once the clients disconnect. Run with -race to catch data races on
// the shared relay and NAT table.
func TestAssociateScaleNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short")
	}
	udpEcho := startUDPEcho(t)
	var cc connCounter
	s := &socksServer{settings: testSettingsIdleFlows(30*time.Second, 64), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	addr, stop := startServer(t, s)
	defer stop()

	runAssociation(t, addr, 8) // warmup
	waitConns(t, &cc, 0, 3*time.Second)
	runtime.GC()
	base := runtime.NumGoroutine()

	const associations = 40
	const dests = 12
	var wg sync.WaitGroup
	for i := 0; i < associations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runAssociation(t, addr, dests)
		}()
	}
	wg.Wait()

	// All clients disconnected: everything must be reclaimed.
	waitConns(t, &cc, 0, 10*time.Second)
	waitGoroutines(t, base+10, 10*time.Second)
}

// TestAssociateServerShutdownReclaims verifies canceling the server context
// tears down in-flight associations (not just client-initiated close).
func TestAssociateServerShutdownReclaims(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter

	s := &socksServer{settings: testSettingsIdle(30 * time.Second), Dial: echoDial("", udpEcho, &cc), ValidUser: allowAll}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var srvWG sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srvWG.Add(1)
			go func() {
				defer srvWG.Done()
				s.ServeConn(ctx, conn)
			}()
		}
	}()

	tc := dialClient(t, ln.Addr().String())
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)
	for i := 0; i < 4; i++ {
		dst := &AddrSpec{IP: net.IPv4(10, 3, 0, byte(i+1)).To4(), Port: 8000 + i}
		sendDatagram(t, uc, bnd, dst, []byte("x"))
		recvDatagram(t, uc, time.Second)
	}
	if cc.live() == 0 {
		t.Fatal("expected open flows before shutdown")
	}

	// socksServer shutdown must reclaim the association even though the client never
	// closed its control connection.
	cancel()
	ln.Close()
	done := make(chan struct{})
	go func() { srvWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not tear down associations on shutdown")
	}
	waitConns(t, &cc, 0, 3*time.Second)
	tc.close()
}
