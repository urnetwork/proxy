package proxy

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestAssociateFailedDialKeepsLiveFlows is the regression test for evicting
// before dialing. At capacity, openFlow used to make room FIRST and dial second,
// so a destination that could not be dialed still cost a healthy live flow. A
// client retrying an undialable destination would progressively tear down its own
// working mappings.
func TestAssociateFailedDialKeepsLiveFlows(t *testing.T) {
	udpEcho := startUDPEcho(t)
	var cc connCounter

	const cap = 2
	dialable := func(addr string) bool { return addr != "203.0.113.9:9" }

	s := &socksServer{
		settings: testSettingsIdleFlows(30*time.Second, cap), ValidUser: allowAll,
		Dial: func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
			if !dialable(addr) {
				return nil, fmt.Errorf("no route to host")
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "udp", udpEcho.String())
			if err != nil {
				return nil, err
			}
			cc.opened.Add(1)
			return &countingConn{Conn: conn, c: &cc}, nil
		},
	}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	// fill the table to capacity with healthy flows
	good := []*AddrSpec{
		{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 1001},
		{IP: net.IPv4(10, 0, 0, 2).To4(), Port: 1002},
	}
	for _, dst := range good {
		sendDatagram(t, uc, bnd, dst, []byte("hi"))
		if _, _, err := recvDatagram(t, uc, 2*time.Second); err != nil {
			t.Fatalf("warmup %v: %v", dst, err)
		}
	}
	if cc.live() != cap {
		t.Fatalf("live flows = %d, want %d", cc.live(), cap)
	}

	// now hammer an undialable destination: each attempt must cost nothing
	bad := &AddrSpec{IP: net.IPv4(203, 0, 113, 9).To4(), Port: 9}
	for i := 0; i < 5; i += 1 {
		sendDatagram(t, uc, bnd, bad, []byte("nope"))
		time.Sleep(50 * time.Millisecond)
	}

	if live := cc.live(); live != cap {
		t.Fatalf("live flows = %d after failed dials, want %d: a failed dial evicted a healthy flow", live, cap)
	}

	// and both healthy flows must still work end to end
	for _, dst := range good {
		sendDatagram(t, uc, bnd, dst, []byte("still-here"))
		_, payload, err := recvDatagram(t, uc, 2*time.Second)
		if err != nil {
			t.Fatalf("flow %v was destroyed by an unrelated failed dial: %v", dst, err)
		}
		if string(payload) != "still-here" {
			t.Fatalf("flow %v payload = %q", dst, payload)
		}
	}
}

// TestAssociateInboundTrafficRefreshesIdle is the regression test for anchoring
// the idle timer to outbound activity only. A client that sends one request and
// then only listens (a UDP media or push stream) had its flow reclaimed a TTL
// after its last send, even while packets were still arriving. Worse, the
// re-created flow dials from a new egress port, so the sender keeps talking to a
// dead port: the stream breaks permanently rather than pausing.
func TestAssociateInboundTrafficRefreshesIdle(t *testing.T) {
	// a backend that, once poked, streams back continuously
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { backend.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			_, peer, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// stream back for a while without the client ever sending again
			go func(peer *net.UDPAddr) {
				for i := 0; i < 40; i += 1 {
					if _, err := backend.WriteToUDP([]byte("tick"), peer); err != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}(peer)
		}
	}()

	var cc connCounter
	s := &socksServer{
		settings: testSettingsIdle(300 * time.Millisecond), ValidUser: allowAll,
		// short TTL: with an outbound-only idle anchor the flow would be reclaimed
		// mid-stream, well before the backend finishes sending
		Dial: func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "udp", backend.LocalAddr().String())
			if err != nil {
				return nil, err
			}
			cc.opened.Add(1)
			return &countingConn{Conn: conn, c: &cc}, nil
		},
	}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	sendDatagram(t, uc, bnd, dst, []byte("subscribe"))

	// the client never sends again; it must keep receiving for well past the TTL
	deadline := time.Now().Add(1500 * time.Millisecond)
	received := 0
	for time.Now().Before(deadline) {
		_, payload, err := recvDatagram(t, uc, 500*time.Millisecond)
		if err != nil {
			break
		}
		if string(payload) == "tick" {
			received += 1
		}
	}

	// 1.5s at a 300ms TTL is 5 TTLs: an outbound-only anchor reclaims the flow
	// after the first one, so only a handful of ticks would arrive
	if received < 15 {
		t.Fatalf("received only %d inbound datagrams across 5 idle-TTL windows: "+
			"a receive-only flow is being reclaimed while it is still active", received)
	}
	if opened := cc.opened.Load(); opened != 1 {
		t.Fatalf("the flow was re-dialed %d times: re-dialing takes a new egress port and breaks the stream", opened)
	}
}

// TestAssociateUndeliverableReplyKeepsFlow is the regression test for tearing the
// whole flow down on any reply write error. One undeliverable datagram (an
// oversized one, or a transient send-buffer error) must cost that datagram, not
// the client's NAT mapping.
func TestAssociateUndeliverableReplyKeepsFlow(t *testing.T) {
	// a backend that replies with an oversized payload first, then a normal one
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { backend.Close() })

	var replies atomic.Int64
	go func() {
		buf := make([]byte, 65535)
		for {
			_, peer, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			n := replies.Add(1)
			if n == 1 {
				// a payload large enough that prefixing the SOCKS header pushes the
				// reply past the maximum UDP datagram, so the relay's write fails
				big := make([]byte, 65500)
				backend.WriteToUDP(big, peer)
				return
			}
		}
	}()

	var cc connCounter
	s := &socksServer{
		settings: testSettingsIdle(30 * time.Second), ValidUser: allowAll,
		Dial: func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "udp", backend.LocalAddr().String())
			if err != nil {
				return nil, err
			}
			cc.opened.Add(1)
			return &countingConn{Conn: conn, c: &cc}, nil
		},
	}
	addr, stop := startServer(t, s)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	sendDatagram(t, uc, bnd, dst, []byte("big-please"))

	// the oversized reply may or may not be deliverable depending on the platform's
	// UDP limits; either way the flow must survive it
	recvDatagram(t, uc, 500*time.Millisecond)

	time.Sleep(200 * time.Millisecond)
	if live := cc.live(); live != 1 {
		t.Fatalf("live flows = %d after an undeliverable reply, want 1: one bad datagram destroyed the mapping", live)
	}
	if opened := cc.opened.Load(); opened != 1 {
		t.Fatalf("flow was re-dialed %d times, want 1", opened)
	}
}
