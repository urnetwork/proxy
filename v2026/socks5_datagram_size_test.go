package proxy

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// The associate relay carries datagrams up to MaxDatagramSize and DROPS anything
// larger. It must never TRUNCATE — forwarding a partial payload is silent data
// corruption, and neither peer would ever learn of it.
//
// These tests pin the boundary from both directions and both sides, because the
// failure they guard against is invisible: a truncating relay looks completely
// healthy, it just quietly mangles large datagrams.

// sizedUdpBackend echoes what it receives and can be told to reply with a payload
// of an exact size. It records the largest payload it actually received, which is
// how a truncated forward is detected.
type sizedUdpBackend struct {
	conn     *net.UDPConn
	maxRecv  atomic.Int64
	recvd    atomic.Int64
	replyLen atomic.Int64
}

func newSizedUdpBackend(t *testing.T) *sizedUdpBackend {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	backend := &sizedUdpBackend{conn: conn}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			backend.recvd.Add(1)
			if int64(n) > backend.maxRecv.Load() {
				backend.maxRecv.Store(int64(n))
			}
			if size := backend.replyLen.Load(); 0 < size {
				reply := bytes.Repeat([]byte("R"), int(size))
				conn.WriteToUDP(reply, peer)
			}
		}
	}()
	return backend
}

func (self *sizedUdpBackend) addr() string { return self.conn.LocalAddr().String() }

func newDatagramSizeServer(t *testing.T, backend *sizedUdpBackend, maxDatagramSize int) (string, func()) {
	t.Helper()
	settings := testSettings()
	settings.AssociateIdleTimeout = 30 * time.Second
	settings.MaxDatagramSize = maxDatagramSize

	server := &socksServer{
		settings:  settings,
		ValidUser: allowAll,
		Dial: func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", backend.addr())
		},
	}
	return startServer(t, server)
}

// TestAssociateRelaysExactlyMaxDatagram pins the boundary as INCLUSIVE: a payload
// of exactly MaxDatagramSize is legal and must arrive whole.
func TestAssociateRelaysExactlyMaxDatagram(t *testing.T) {
	const maxSize = 2048
	backend := newSizedUdpBackend(t)
	addr, stop := newDatagramSizeServer(t, backend, maxSize)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	payload := bytes.Repeat([]byte("A"), maxSize)
	sendDatagram(t, uc, bnd, dst, payload)

	deadline := time.Now().Add(2 * time.Second)
	for backend.recvd.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := backend.maxRecv.Load(); got != maxSize {
		t.Fatalf("destination received %d bytes, want exactly %d: a legal max-size datagram was dropped or truncated",
			got, maxSize)
	}
}

// TestAssociateDropsOversizeClientDatagram is the core guarantee in the
// client->destination direction. The destination must receive NOTHING — not a
// truncated payload.
func TestAssociateDropsOversizeClientDatagram(t *testing.T) {
	const maxSize = 2048
	backend := newSizedUdpBackend(t)
	addr, stop := newDatagramSizeServer(t, backend, maxSize)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}

	// one byte over the limit
	sendDatagram(t, uc, bnd, dst, bytes.Repeat([]byte("A"), maxSize+1))
	// comfortably over, to catch a relay that only rejects the exact +1 case
	sendDatagram(t, uc, bnd, dst, bytes.Repeat([]byte("A"), maxSize*4))

	time.Sleep(500 * time.Millisecond)

	if got := backend.recvd.Load(); got != 0 {
		t.Fatalf("destination received %d datagram(s) of at most %d bytes: an oversize datagram was TRUNCATED and forwarded, "+
			"which silently corrupts the payload", got, backend.maxRecv.Load())
	}

	// and the association must still work: an oversize datagram costs that
	// datagram, not the client's session
	sendDatagram(t, uc, bnd, dst, []byte("still-here"))
	deadline := time.Now().Add(2 * time.Second)
	for backend.recvd.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if backend.recvd.Load() == 0 {
		t.Fatal("the association stopped working after an oversize datagram")
	}
	if got := backend.maxRecv.Load(); got != int64(len("still-here")) {
		t.Fatalf("destination received %d bytes, want %d", got, len("still-here"))
	}
}

// TestAssociateDropsOversizeReply is the same guarantee in the destination->client
// direction: the client must never see a truncated reply.
func TestAssociateDropsOversizeReply(t *testing.T) {
	const maxSize = 2048
	backend := newSizedUdpBackend(t)
	backend.replyLen.Store(maxSize + 1) // one byte over
	addr, stop := newDatagramSizeServer(t, backend, maxSize)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	sendDatagram(t, uc, bnd, dst, []byte("give-me-a-big-one"))

	if _, payload, err := recvDatagram(t, uc, 700*time.Millisecond); err == nil {
		t.Fatalf("client received a %d byte reply to an oversize (%d byte) datagram: it was TRUNCATED, "+
			"which silently corrupts the payload", len(payload), maxSize+1)
	}

	// the flow must survive: a legal reply still gets through afterwards
	backend.replyLen.Store(maxSize)
	sendDatagram(t, uc, bnd, dst, []byte("now-a-legal-one"))
	_, payload, err := recvDatagram(t, uc, 2*time.Second)
	if err != nil {
		t.Fatalf("the flow was destroyed by an oversize reply: %v", err)
	}
	if len(payload) != maxSize {
		t.Fatalf("reply payload = %d bytes, want %d", len(payload), maxSize)
	}
}

// TestAssociateDropsOversizePayloadUnderSmallHeader covers the case the buffer
// check cannot catch alone. The SOCKS header is 10 bytes for IPv4 but up to 262
// for a domain name, so a datagram with a SMALL header can carry an oversize
// payload and still fit inside the read buffer. Only an explicit payload-length
// check rejects it.
func TestAssociateDropsOversizePayloadUnderSmallHeader(t *testing.T) {
	// a small limit makes the header/payload asymmetry easy to exercise
	const maxSize = 64
	backend := newSizedUdpBackend(t)
	addr, stop := newDatagramSizeServer(t, backend, maxSize)
	defer stop()

	tc := dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	// an IPv4 header is 10 bytes, so header+payload here is 10+200 = 210, well
	// inside the read buffer (which is sized for a 262-byte header) — yet the
	// payload is far over the limit
	dst := &AddrSpec{IP: net.IPv4(9, 9, 9, 9).To4(), Port: 53}
	sendDatagram(t, uc, bnd, dst, bytes.Repeat([]byte("A"), 200))

	time.Sleep(400 * time.Millisecond)
	if got := backend.recvd.Load(); got != 0 {
		t.Fatalf("destination received a %d byte payload over a %d byte limit: an oversize payload slipped "+
			"through under a small header", backend.maxRecv.Load(), maxSize)
	}
}

// TestMaxUdpReadLenLeavesRoomForDetection pins the buffer arithmetic that makes
// oversize datagrams detectable at all: the read buffer must be strictly larger
// than the largest datagram we accept, or a full read is ambiguous.
func TestMaxUdpReadLenLeavesRoomForDetection(t *testing.T) {
	for _, maxSize := range []int{64, 1500, 2048, 9000} {
		readLen := socksMaxUdpReadLen(maxSize)
		largestLegal := maxDatagramHeaderLen + maxSize
		if readLen <= largestLegal {
			t.Fatalf("socksMaxUdpReadLen(%d) = %d, which is not larger than the largest legal datagram (%d): "+
				"a read that fills the buffer would be indistinguishable from a truncated one",
				maxSize, readLen, largestLegal)
		}
	}
}

// TestDefaultMaxDatagramSize pins the product decision: a 4kib MTU, which covers
// EDNS0's classic advertised buffer so large DNSSEC responses are relayed rather
// than silently dropped.
func TestDefaultMaxDatagramSize(t *testing.T) {
	if got := DefaultSocksProxySettings().MaxDatagramSize; got != 4096 {
		t.Fatalf("default MaxDatagramSize = %d, want 4096", got)
	}
}
