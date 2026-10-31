package proxy

// Covers configuration changes on existing eager and on-demand clients.

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/v2026/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Generates independent preshared keys for update and clearing checks.
func newReconcilePresharedKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Both reconciliation entry points replace a live peer when its handshake
// secret changes, including clearing it and recreating without an endpoint.
func TestWgProxyOnDemandPresharedKeyChangesReachLivePeer(t *testing.T) {
	for _, operation := range []string{"add", "set"} {
		for _, seeded := range []bool{false, true} {
			func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				server := startOnDemandWgProxy(t, ctx, nil)
				client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.21"))
				config := client.wgClient()
				config.PresharedKey = newReconcilePresharedKey(t).String()
				config.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.100:12345"))
				if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: config}); err != nil {
					t.Fatal(err)
				}
				for _, presharedKey := range []wgtypes.Key{newReconcilePresharedKey(t), {}} {
					updated := *config
					if presharedKey == (wgtypes.Key{}) {
						updated.PresharedKey = ""
					} else {
						updated.PresharedKey = presharedKey.String()
					}
					if !seeded {
						updated.Endpoint = nil
					}
					var err error
					if operation == "add" {
						_, err = server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: &updated})
					} else {
						err = server.wg.SetClients(map[netip.Addr]*WgClient{client.ip: &updated})
					}
					if err != nil {
						t.Fatal(err)
					}
					if !seeded {
						// This public path resolves and creates the newly configured
						// peer; sending fails because it has no endpoint yet.
						_ = server.wg.InitiateHandshake(client.ip)
					}
					state, err := server.wg.device.IpcGet()
					if err != nil {
						t.Fatal(err)
					}
					if len(state.Peers) != 1 || state.Peers[0].PresharedKey != presharedKey {
						t.Fatalf("%s seeded=%t retained the previous handshake secret", operation, seeded)
					}
					config = &updated
				}
			}()
		}
	}
}

// An unchanged snapshot preserves a live session; endpoint refreshes apply
// without rebuilding that session or losing its allowed address.
func TestWgProxyOnDemandUnchangedConfigPreservesPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.22"))
	config := client.wgClient()
	config.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.100:12345"))
	clients := map[netip.Addr]*WgClient{client.ip: config}
	if _, err := server.wg.AddClients(clients); err != nil {
		t.Fatal(err)
	}
	peer := server.wg.device.LookupPeer(device.NoisePublicKey(client.publicKey))
	for _, operation := range []string{"add", "set"} {
		var err error
		if operation == "add" {
			_, err = server.wg.AddClients(clients)
		} else {
			err = server.wg.SetClients(clients)
		}
		if err != nil {
			t.Fatal(err)
		}
		if server.wg.device.LookupPeer(device.NoisePublicKey(client.publicKey)) != peer {
			t.Fatalf("%s rebuilt an unchanged peer", operation)
		}
	}
}

// Moving a key through SetClients keeps its new endpoint and route available
// for the server's first handshake, including when two keys swap addresses.
func TestWgProxyOnDemandSetClientsPreservesMovedSeededPeers(t *testing.T) {
	for _, swap := range []bool{false, true} {
		func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := startOnDemandWgProxy(t, ctx, nil)
			first := newOnDemandClient(t, netip.MustParseAddr("192.0.2.23"))
			second := newOnDemandClient(t, netip.MustParseAddr("192.0.2.24"))
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			endpoint := listener.LocalAddr().(*net.UDPAddr)
			firstConfig, secondConfig := first.wgClient(), second.wgClient()
			firstConfig.Endpoint, secondConfig.Endpoint = endpoint, endpoint
			clients := map[netip.Addr]*WgClient{first.ip: firstConfig}
			if swap {
				clients[second.ip] = secondConfig
			}
			if _, err := server.wg.AddClients(clients); err != nil {
				t.Fatal(err)
			}
			movedFirst, movedSecond := *firstConfig, *secondConfig
			movedFirst.ClientIpv4, movedSecond.ClientIpv4 = second.ip, first.ip
			clients = map[netip.Addr]*WgClient{second.ip: &movedFirst}
			if swap {
				clients[first.ip] = &movedSecond
			}
			if err := server.wg.SetClients(clients); err != nil {
				t.Fatal(err)
			}
			statuses, err := server.wg.PeerStatuses()
			if err != nil {
				t.Fatal(err)
			}
			if server.wg.ClientCount() != len(clients) || server.wg.PeerCount() != len(clients) || len(statuses) != len(clients) {
				t.Fatalf("swap=%t lost a moved client's seeded peer", swap)
			}
			for addr, client := range clients {
				status := statuses[addr]
				if status == nil || status.PublicKey != client.PublicKey || status.Endpoint == nil || status.Endpoint.String() != endpoint.String() {
					t.Fatalf("swap=%t lost identity or endpoint at %s", swap, addr)
				}
				if err := server.wg.InitiateHandshake(addr); err != nil {
					t.Fatalf("server-first handshake for %s: %v", addr, err)
				}
				if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				packet := make([]byte, device.MessageInitiationSize)
				if count, _, err := listener.ReadFromUDP(packet); err != nil || count != len(packet) {
					t.Fatalf("server-first initiation did not reach the seeded endpoint: bytes=%d err=%v", count, err)
				}
			}
			state, err := server.wg.device.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			for _, peer := range state.Peers {
				if len(peer.AllowedIPs) != 1 {
					t.Fatal("moved peer lost its allowed address")
				}
				addr, ok := netip.AddrFromSlice(peer.AllowedIPs[0].IP)
				client := clients[addr.Unmap()]
				if !ok || client == nil || client.PublicKey != peer.PublicKey.String() {
					t.Fatal("moved peer retained its previous allowed address")
				}
			}
		}()
	}
}

// Replacing an eager client's key must remove its former status mapping,
// including after that address is removed through the public API.
func TestWgProxyEagerStatusesForgetReplacedKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, func(settings *WgProxySettings) { settings.PeersOnDemand = false })
	old := newOnDemandClient(t, netip.MustParseAddr("192.0.2.25"))
	replacement := newOnDemandClient(t, old.ip)
	for _, client := range []*onDemandClient{old, replacement} {
		if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.wg.RemoveClients(time.Now().Add(time.Hour), old.ip); err != nil {
		t.Fatal(err)
	}
	statuses, err := server.wg.PeerStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if server.wg.ClientCount() != 0 || len(statuses) != 0 {
		t.Fatal("replaced key was exported after the registered client was removed")
	}
}

// A pending control operation owns client configuration until publication.
// Handshake initiation must resolve its client only after that operation ends.
func TestWgProxyOnDemandInitiateHandshakeWaitsForReconciliation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.26"))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
		t.Fatal(err)
	}
	server.wg.controlLock.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			server.wg.controlLock.Unlock()
		}
	}()
	result := make(chan error, 1)
	go func() { result <- server.wg.InitiateHandshake(client.ip) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	stack := make([]byte, 1024*1024)
	blocked := false
	for !blocked {
		select {
		case err := <-result:
			t.Fatalf("handshake used configuration during a pending control operation: %v", err)
		case <-deadline.C:
			t.Fatal("handshake neither waited for control operation nor completed")
		default:
		}
		length := runtime.Stack(stack, true)
		for _, goroutine := range bytes.Split(stack[:length], []byte("\n\n")) {
			header, _, _ := bytes.Cut(goroutine, []byte("\n"))
			if bytes.Contains(header, []byte("[sync.")) && bytes.Contains(goroutine, []byte("(*WgProxy).InitiateHandshake(")) && bytes.Contains(goroutine, []byte("sync.(*Mutex).Lock(")) {
				blocked = true
			}
		}
		runtime.Gosched()
	}
	if err := server.wg.removeClientsWithLock(nil, client.ip); err != nil {
		t.Fatal(err)
	}
	server.wg.controlLock.Unlock()
	unlocked = true
	select {
	case err := <-result:
		if err == nil || server.wg.PeerCount() != 0 {
			t.Fatal("handshake recreated the removed client")
		}
	case <-deadline.C:
		t.Fatal("handshake did not finish after reconciliation")
	}
}

// Holds one selected attachment call before it changes the external tun.
type reconcileGateTun struct {
	*recordingWgTun
	holdNil bool
	armed   atomic.Bool
	held    atomic.Bool
	entered chan struct{}
	release chan struct{}
}

// Pauses only the chosen call; newer attachment decisions may complete first.
func (self *reconcileGateTun) SetReceive(receive chan []byte) {
	self.waitForReceive(receive)
	self.recordingWgTun.SetReceive(receive)
}

// Shares the barrier between legacy and address-aware setters.
func (self *reconcileGateTun) waitForReceive(receive chan []byte) {
	if self.armed.Load() && (receive == nil) == self.holdNil && self.held.CompareAndSwap(false, true) {
		close(self.entered)
		<-self.release
	}
}

// Models the hosted device's single address/channel slot, including a nil
// update that clears it even when the caller supplies an older address.
type reconcileAddressTun struct {
	*reconcileGateTun
	addr netip.Addr
}

// Changes address and channel together, after the selected barrier releases.
func (self *reconcileAddressTun) SetReceiveForAddress(addr netip.Addr, receive chan []byte) {
	self.waitForReceive(receive)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if receive == nil {
		addr = netip.Addr{}
	}
	self.addr, self.receive = addr, receive
}

// A delayed eviction detach must reconcile a replacement peer's newer
// attachment, without blocking either its configuration or its first packet.
func TestWgProxyOnDemandEvictionPreservesReactivatedAttachment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.27"))
	tun := &reconcileGateTun{
		recordingWgTun: newRecordingWgTun(),
		holdNil:        true,
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(tun.release) })
	defer release()
	config := client.wgClient()
	config.Tun = func() (WgTun, error) { return tun, nil }
	config.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.100:12345"))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: config}); err != nil {
		t.Fatal(err)
	}
	packet := udpIPv4Packet(client.ip, netip.MustParseAddr("203.0.113.1"), []byte("attachment"))
	if _, err := server.wg.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	tun.armed.Store(true)
	removed := make(chan int, 1)
	go func() { removed <- server.wg.evictIdlePeers(-time.Hour) }()
	select {
	case <-tun.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction did not reach detach")
	}
	if server.wg.PeerCount() != 0 {
		t.Fatal("eviction did not remove the old peer")
	}
	if _, err := server.wg.SeedEndpoints(map[netip.Addr]*net.UDPAddr{client.ip: config.Endpoint}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.wg.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case count := <-removed:
		if count != 1 {
			t.Fatalf("evicted %d peers, want 1", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("eviction did not finish")
	}
	tun.stateLock.Lock()
	receive := tun.receive
	tun.stateLock.Unlock()
	if receive != server.wg.receive || server.wg.PeerCount() != 1 {
		t.Fatal("old eviction detached the replacement peer's live tunnel")
	}
}

// A new packet can also arrive between device removal and selection of tuns
// to detach. Activity since the eviction snapshot preserves that attachment.
func TestWgProxyOnDemandEvictionSkipsNewerActivity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.29"))
	config := client.wgClient()
	config.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.100:12345"))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: config}); err != nil {
		t.Fatal(err)
	}
	packet := udpIPv4Packet(client.ip, netip.MustParseAddr("203.0.113.1"), []byte("new activity"))
	if _, err := server.wg.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	// Split the eviction pass at its device boundary to choose the exact
	// interleaving, without relying on a second packet winning a race.
	activities := server.wg.snapshotClientActivities()
	removed := server.wg.device.RemoveIdlePeers(-time.Hour)
	if len(removed) != 1 {
		t.Fatalf("evicted %d peers, want 1", len(removed))
	}
	if _, err := server.wg.SeedEndpoints(map[netip.Addr]*net.UDPAddr{client.ip: config.Endpoint}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.wg.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	server.wg.detachKeys(removed, activities)
	client.proxyTun.stateLock.Lock()
	receive := client.proxyTun.receive
	client.proxyTun.stateLock.Unlock()
	if receive != server.wg.receive || server.wg.PeerCount() != 1 {
		t.Fatal("eviction removed an attachment that became active after its snapshot")
	}
}

// Reconciliation follows a hosted tun to its new address even if an old
// eviction's external detach completes after the move and its first packet.
func TestWgProxyOnDemandEvictionPreservesMovedAttachment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.30"))
	movedAddr := netip.MustParseAddr("192.0.2.31")
	tun := &reconcileAddressTun{reconcileGateTun: &reconcileGateTun{
		recordingWgTun: newRecordingWgTun(),
		holdNil:        true,
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}}
	release := sync.OnceFunc(func() { close(tun.release) })
	defer release()
	config := client.wgClient()
	config.Tun = func() (WgTun, error) { return tun, nil }
	config.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.100:12345"))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: config}); err != nil {
		t.Fatal(err)
	}
	packet := func(addr netip.Addr) []byte {
		return udpIPv4Packet(addr, netip.MustParseAddr("203.0.113.1"), []byte("moved attachment"))
	}
	if _, err := server.wg.Write([][]byte{packet(client.ip)}, 0); err != nil {
		t.Fatal(err)
	}
	tun.armed.Store(true)
	removed := make(chan int, 1)
	go func() { removed <- server.wg.evictIdlePeers(-time.Hour) }()
	select {
	case <-tun.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction did not reach detach")
	}
	moved := *config
	moved.ClientIpv4 = movedAddr
	if err := server.wg.SetClients(map[netip.Addr]*WgClient{movedAddr: &moved}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.wg.Write([][]byte{packet(movedAddr)}, 0); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction did not finish")
	}
	tun.stateLock.Lock()
	addr, receive := tun.addr, tun.receive
	tun.stateLock.Unlock()
	if addr != movedAddr || receive != server.wg.receive {
		t.Fatal("old eviction detached the hosted tun at its new address")
	}
}

// The inverse ordering must also converge: a packet's delayed reattachment
// cannot restore return routing after the client has been removed.
func TestWgProxyOnDemandRemovalRejectsDelayedAttachment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, netip.MustParseAddr("192.0.2.28"))
	tun := &reconcileGateTun{
		recordingWgTun: newRecordingWgTun(),
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(tun.release) })
	defer release()
	config := client.wgClient()
	config.Tun = func() (WgTun, error) { return tun, nil }
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: config}); err != nil {
		t.Fatal(err)
	}
	packet := udpIPv4Packet(client.ip, netip.MustParseAddr("203.0.113.1"), []byte("attachment"))
	if _, err := server.wg.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	tun.armed.Store(true)
	written := make(chan error, 1)
	go func() { _, err := server.wg.Write([][]byte{packet}, 0); written <- err }()
	select {
	case <-tun.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("packet did not reach attachment")
	}
	if err := server.wg.RemoveClients(time.Now().Add(time.Hour), client.ip); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet did not finish")
	}
	tun.stateLock.Lock()
	receive := tun.receive
	tun.stateLock.Unlock()
	if receive != nil || server.wg.ClientCount() != 0 {
		t.Fatal("old packet reattached a removed client")
	}
}
