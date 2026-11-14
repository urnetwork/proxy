package proxy

import (
	"net/netip"
	"testing"
)

type recordingAddressTun struct {
	legacyCalls int
	address     netip.Addr
	receive     chan []byte
}

func (t *recordingAddressTun) Active() bool         { return true }
func (t *recordingAddressTun) UpdateActivity() bool { return true }
func (t *recordingAddressTun) Send([]byte) bool     { return true }
func (t *recordingAddressTun) Cancel()              {}
func (t *recordingAddressTun) SetReceive(receive chan []byte) {
	t.legacyCalls++
	t.receive = receive
}
func (t *recordingAddressTun) SetReceiveForAddress(address netip.Addr, receive chan []byte) {
	t.address = address
	t.receive = receive
}

// WireGuard knows the assigned peer address at every attach/detach site. It
// must preserve that address when the backing tunnel supports demultiplexing;
// falling back to the legacy global switch makes simultaneous HTTP/SOCKS and
// WireGuard traffic mutually destructive.
func TestSetWgTunReceiveUsesAddressAwareRouting(t *testing.T) {
	tun := &recordingAddressTun{}
	receive := make(chan []byte, 1)
	address := netip.MustParseAddr("10.55.66.77")

	setWgTunReceive(tun, address, receive)
	if tun.legacyCalls != 0 {
		t.Fatalf("legacy SetReceive called %d times", tun.legacyCalls)
	}
	if tun.address != address || tun.receive != receive {
		t.Fatalf("address-aware receive = (%s, %p), want (%s, %p)", tun.address, tun.receive, address, receive)
	}

	setWgTunReceive(tun, address, nil)
	if tun.address != address || tun.receive != nil {
		t.Fatalf("address-aware detach = (%s, %p), want (%s, nil)", tun.address, tun.receive, address)
	}
}

type recordingLegacyTun struct {
	receive chan []byte
}

func (t *recordingLegacyTun) Active() bool                   { return true }
func (t *recordingLegacyTun) UpdateActivity() bool           { return true }
func (t *recordingLegacyTun) Send([]byte) bool               { return true }
func (t *recordingLegacyTun) SetReceive(receive chan []byte) { t.receive = receive }
func (t *recordingLegacyTun) Cancel()                        {}

func TestSetWgTunReceiveKeepsLegacyCompatibility(t *testing.T) {
	tun := &recordingLegacyTun{}
	receive := make(chan []byte, 1)
	setWgTunReceive(tun, netip.MustParseAddr("10.55.66.77"), receive)
	if tun.receive != receive {
		t.Fatal("legacy WgTun did not receive the shared channel")
	}
}
