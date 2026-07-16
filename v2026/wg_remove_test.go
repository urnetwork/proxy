package proxy

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// teardownWgTun records the teardown calls a removed client's tun must receive.
type teardownWgTun struct {
	canceled     atomic.Int64
	receiveNiled atomic.Int64

	stateLock sync.Mutex
	receive   chan []byte
}

func (self *teardownWgTun) Active() bool         { return true }
func (self *teardownWgTun) UpdateActivity() bool { return true }
func (self *teardownWgTun) Send([]byte) bool     { return true }
func (self *teardownWgTun) Cancel()              { self.canceled.Add(1) }

func (self *teardownWgTun) SetReceive(receive chan []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if receive == nil {
		self.receiveNiled.Add(1)
	}
	self.receive = receive
}

// wgTestAddrs hands out unique client addresses across calls, so clients added
// by separate calls never collide (a collision would silently re-add the same
// client and reset its add time).
var wgTestAddrs atomic.Int64

// addWgClients registers n clients with the given tun factory.
func addWgClients(t *testing.T, wg *WgProxy, n int, tun func() (WgTun, error)) []netip.Addr {
	t.Helper()
	clients := map[netip.Addr]*WgClient{}
	addrs := []netip.Addr{}
	for i := 0; i < n; i += 1 {
		_, publicKey, err := WgGenKeyPairStrings()
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		id := wgTestAddrs.Add(1)
		addr := netip.AddrFrom4([4]byte{10, byte(id >> 16), byte(id >> 8), byte(id)})
		addrs = append(addrs, addr)
		clients[addr] = &WgClient{
			PublicKey:  publicKey,
			ClientIpv4: addr,
			Tun:        tun,
		}
	}
	applied, err := wg.AddClients(clients)
	if err != nil {
		t.Fatalf("AddClients: %v", err)
	}
	if len(applied) != n {
		t.Fatalf("AddClients applied %d clients, want %d", len(applied), n)
	}
	return addrs
}

// TestWgProxyRemoveClientsBatches covers removal across several batches. Removal
// used to issue one device transaction per peer while holding controlLock, so a
// reconcile pass dropping a large stale set stalled every concurrent AddClients
// (a new client's very first connection) behind thousands of serial round trips.
// Batching must not change what ends up removed.
func TestWgProxyRemoveClientsBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := DefaultWgProxySettings()
	settings.ClientBatchSize = 2
	wg := NewWgProxy(ctx, settings)
	defer wg.Close()

	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }
	addrs := addWgClients(t, wg, 5, tun)

	// removal spans three batches at ClientBatchSize=2
	if err := wg.RemoveClients(time.Now(), addrs...); err != nil {
		t.Fatalf("RemoveClients: %v", err)
	}

	if count := wg.ClientCount(); count != 0 {
		t.Fatalf("ClientCount = %d after removing every client, want 0", count)
	}
	dev, err := wg.device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if len(dev.Peers) != 0 {
		t.Fatalf("device still has %d peers after removing every client", len(dev.Peers))
	}
	if times := wg.Clients(); len(times) != 0 {
		t.Fatalf("Clients returned %d add times after removal, want 0", len(times))
	}
}

// TestWgProxyRemoveClientsBatchRespectsCutoff checks the grace window survives
// batching: a client applied at or after the cutoff must be kept even when its
// batch-mates are removed.
func TestWgProxyRemoveClientsBatchRespectsCutoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := DefaultWgProxySettings()
	settings.ClientBatchSize = 2
	wg := NewWgProxy(ctx, settings)
	defer wg.Close()

	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }
	stale := addWgClients(t, wg, 4, tun)

	cutoff := time.Now()
	time.Sleep(10 * time.Millisecond)

	// applied after the cutoff: immune this pass
	fresh := addWgClients(t, wg, 2, tun)

	all := append(append([]netip.Addr{}, stale...), fresh...)
	if err := wg.RemoveClients(cutoff, all...); err != nil {
		t.Fatalf("RemoveClients: %v", err)
	}

	if count := wg.ClientCount(); count != len(fresh) {
		t.Fatalf("ClientCount = %d, want %d: the cutoff grace window was not respected across batches", count, len(fresh))
	}
	remaining := wg.Clients()
	for _, addr := range fresh {
		if _, ok := remaining[addr]; !ok {
			t.Fatalf("client %s was applied after the cutoff but was removed anyway", addr)
		}
	}
	for _, addr := range stale {
		if _, ok := remaining[addr]; ok {
			t.Fatalf("stale client %s survived removal", addr)
		}
	}
}

// TestWgProxyRemoveClientsTearsDownActiveTuns checks batching still tears down a
// removed client's active tun: leaving it live would leak the device and keep
// routing packets for a client that no longer exists.
func TestWgProxyRemoveClientsTearsDownActiveTuns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := DefaultWgProxySettings()
	settings.ClientBatchSize = 2
	wg := NewWgProxy(ctx, settings)
	defer wg.Close()

	tuns := map[netip.Addr]*teardownWgTun{}
	var tunsLock sync.Mutex

	clients := map[netip.Addr]*WgClient{}
	addrs := []netip.Addr{}
	for i := 0; i < 5; i += 1 {
		_, publicKey, err := WgGenKeyPairStrings()
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		addr := netip.AddrFrom4([4]byte{10, 0, 3, byte(i + 1)})
		addrs = append(addrs, addr)
		tun := &teardownWgTun{}
		tunsLock.Lock()
		tuns[addr] = tun
		tunsLock.Unlock()
		clients[addr] = &WgClient{
			PublicKey:  publicKey,
			ClientIpv4: addr,
			Tun:        func() (WgTun, error) { return tun, nil },
		}
	}
	if _, err := wg.AddClients(clients); err != nil {
		t.Fatalf("AddClients: %v", err)
	}

	// activate every client so each has a live tun registered
	for _, addr := range addrs {
		if _, err := wg.activateClient(addr); err != nil {
			t.Fatalf("activateClient %s: %v", addr, err)
		}
	}

	if err := wg.RemoveClients(time.Now(), addrs...); err != nil {
		t.Fatalf("RemoveClients: %v", err)
	}

	tunsLock.Lock()
	defer tunsLock.Unlock()
	for addr, tun := range tuns {
		if tun.canceled.Load() == 0 {
			t.Fatalf("tun for removed client %s was never canceled: the device leaks", addr)
		}
		if tun.receiveNiled.Load() == 0 {
			t.Fatalf("tun for removed client %s still has its receive channel: it keeps routing packets", addr)
		}
	}
}

// TestWgProxyRemoveClientsAtScale is the shape a reconcile pass actually takes:
// a large stale set dropped in one call. It must be correct and must not take the
// serial one-transaction-per-peer path that made mass removal stall the control
// plane.
func TestWgProxyRemoveClientsAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := NewWgProxy(ctx, DefaultWgProxySettings())
	defer wg.Close()

	const clients = 2000
	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }
	addrs := addWgClients(t, wg, clients, tun)

	start := time.Now()
	if err := wg.RemoveClients(time.Now(), addrs...); err != nil {
		t.Fatalf("RemoveClients: %v", err)
	}
	elapsed := time.Since(start)

	if count := wg.ClientCount(); count != 0 {
		t.Fatalf("ClientCount = %d after removing %d clients, want 0", count, clients)
	}
	dev, err := wg.device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if len(dev.Peers) != 0 {
		t.Fatalf("device still has %d peers after mass removal", len(dev.Peers))
	}
	t.Logf("removed %d clients in %s", clients, elapsed)
}

// TestWgProxyRemoveClientsDoesNotBlockAdds is the point of batching: a mass
// removal holds controlLock, so an AddClients for a brand new client (its first
// connection) queues behind it. That wait must stay short.
func TestWgProxyRemoveClientsDoesNotBlockAdds(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := NewWgProxy(ctx, DefaultWgProxySettings())
	defer wg.Close()

	const stale = 2000
	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }
	addrs := addWgClients(t, wg, stale, tun)

	_, publicKey, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	newAddr := netip.AddrFrom4([4]byte{172, 16, 0, 1})
	newClient := map[netip.Addr]*WgClient{
		newAddr: {PublicKey: publicKey, ClientIpv4: newAddr, Tun: tun},
	}

	removed := make(chan struct{})
	go func() {
		defer close(removed)
		if err := wg.RemoveClients(time.Now(), addrs...); err != nil {
			t.Errorf("RemoveClients: %v", err)
		}
	}()

	// the new client must get in without waiting on the whole removal
	start := time.Now()
	if _, err := wg.AddClients(newClient); err != nil {
		t.Fatalf("AddClients during mass removal: %v", err)
	}
	waited := time.Since(start)

	<-removed

	if 10*time.Second < waited {
		t.Fatalf("a new client waited %s behind a mass removal", waited)
	}
	t.Logf("new client admitted after waiting %s behind a %d-client removal", waited, stale)

	if _, ok := wg.Clients()[newAddr]; !ok {
		t.Fatal("the new client was not registered")
	}
}
