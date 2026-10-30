package proxy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	// "strconv"
	"sync"
	"sync/atomic"
	"time"

	uwgtun "github.com/urnetwork/userwireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
)

// The client ipv4 below is the peer's tunnel address inside this server. It is
// NOT what reaches the egress providers: `server/proxy.ProxyDevice` substitutes
// a per-device address from connect's local pool on the way out and restores
// this one on the way back (see its natAddr, and connect.RewriteIpv4Source).
//
// That rewrite is load-bearing rather than cosmetic. A peer's tunnel address is
// allocated from a durable pool and written into its wg config, so threading it
// through unmodified made it stable across sessions AND identical at every
// provider in the peer's window -- which let colluding providers tell that
// those flows belonged to one client, defeating the multi-provider window for
// this path alone. Threat model §9.4.

var DidNotSendError = errors.New("did not send")
var PacketTooLargeError = errors.New("packet too large for buffer")

// MaxClients is the maximum number of clients (peers) a wg device supports
const MaxClients = device.MaxPeers

type WgClient struct {
	PublicKey string
	// TODO this is the signed proxy id
	PresharedKey string
	ClientIpv4   netip.Addr
	Tun          func() (WgTun, error)
	// Endpoint, when set, seeds the peer's endpoint so the SERVER can
	// initiate a handshake (wireguard is symmetric) instead of waiting for
	// the client's dead-session timers. Used by the deploy endpoint handoff
	// (PROXYDRAIN1.md §3.4): the drained instance exports each peer's learned
	// endpoint and the replacement instance applies it here. nil leaves the
	// endpoint to be learned from the client's next packet, as before.
	Endpoint *net.UDPAddr
}

type WgTun interface {
	// CancelIfIdle() bool
	Active() bool
	UpdateActivity() bool
	Send([]byte) bool
	SetReceive(chan []byte)
	Cancel()
}

// WgAddressTun lets a shared packet tunnel route only one WireGuard peer's
// return address to WgProxy while its other consumers remain active. Legacy
// WgTun implementations still receive the process-wide channel through
// SetReceive; production hosted devices implement this address-aware form so
// HTTP, SOCKS, and WireGuard can use one proxy device concurrently.
type WgAddressTun interface {
	WgTun
	SetReceiveForAddress(netip.Addr, chan []byte)
}

func setWgTunReceive(tun WgTun, addr netip.Addr, receive chan []byte) {
	if addressTun, ok := tun.(WgAddressTun); ok {
		addressTun.SetReceiveForAddress(addr, receive)
		return
	}
	tun.SetReceive(receive)
}

// Applies the current attachment without holding the state lock across a tun
// call. If a delayed call races activation or removal, reconcile again before
// returning so it cannot overwrite the newer attachment decision.
func (self *WgProxy) syncTunReceive(tun WgTun, addr netip.Addr) {
	currentAttachment := func() (netip.Addr, chan []byte) {
		if self.ctx != nil && self.ctx.Err() != nil {
			return addr, nil
		}
		self.stateLock.RLock()
		defer self.stateLock.RUnlock()
		if self.activeClients[addr] == tun {
			return addr, self.receive
		}
		// A hosted tun may have moved to another address while an old
		// detach was in flight. Its setter may own a single receive slot.
		currentAddr := netip.Addr{}
		for activeAddr := range self.activeTunAddrs[tun] {
			if !currentAddr.IsValid() || activeAddr.Less(currentAddr) {
				currentAddr = activeAddr
			}
		}
		if currentAddr.IsValid() {
			return currentAddr, self.receive
		}
		return addr, nil
	}
	for {
		currentAddr, receive := currentAttachment()
		if currentAddr != addr {
			setWgTunReceive(tun, addr, nil)
		}
		setWgTunReceive(tun, currentAddr, receive)
		nextAddr, nextReceive := currentAttachment()
		if nextAddr == currentAddr && nextReceive == receive {
			return
		}
	}
}

// Optionally accepts one borrowed packet list. The implementation must copy
// before returning if its asynchronous send retains packet bytes.
type WgBatchTun interface {
	WgTun
	SendBorrowedBatch([][]byte, int) int
}

func DefaultWgProxySettings() *WgProxySettings {
	return &WgProxySettings{
		ReceiveSequenceSize:     1024,
		EventsSequenceSize:      16,
		CheckTunIdleTimeout:     1 * time.Minute,
		ClientBatchSize:         256,
		UploadPacketBatchSize:   8,
		DownloadPacketBatchSize: 64,
		PeersOnDemand:           false,
		// keys are rejected 180 s after the handshake that made them, so a
		// peer this long without one has carried no traffic for minutes
		PeerIdleTimeout:       10 * time.Minute,
		PeerEvictInterval:     1 * time.Minute,
		PeerMissNegativeTtl:   10 * time.Second,
		PeerMissRatePerSecond: 1024,
		PeerMissBurst:         2048,
		// the handler answers from memory; the bound covers scheduling
		// delay on a saturated host, past which the client's retry (after
		// RekeyTimeout) finds the peer the late answer created
		PeerMissHandlerTimeout: 250 * time.Millisecond,
	}
}

type WgProxySettings struct {
	// Log, when set, receives wg device and proxy logging. nil resolves to
	// `connect.DefaultLogger()`.
	Log connect.Logger

	PrivateKey          string
	ReceiveSequenceSize int
	EventsSequenceSize  int
	CheckTunIdleTimeout time.Duration
	FirewallMark        int
	// peers are applied to the device in batches of this size, so that a
	// failing peer drops at most one batch (which is then retried per peer)
	// rather than the entire set
	ClientBatchSize int
	// Maximum borrowed packets handed to one asynchronous Connect upload.
	UploadPacketBatchSize int
	// Maximum already-ready packets returned by one WireGuard read.
	DownloadPacketBatchSize int

	// PeersOnDemand keeps configured clients out of the device until they
	// handshake. AddClients then only indexes a client; the device creates
	// its peer, with the peer's two goroutines and queues, when an
	// initiation from the client's key arrives (userwireguard's miss
	// handler), and the proxy removes the peer after PeerIdleTimeout without
	// a handshake. Peers, goroutines and queues follow use, not
	// configuration. A client added with an Endpoint gets its peer at once,
	// since the server may reach it first.
	PeersOnDemand bool
	// An on-demand peer with no handshake for this long is removed; checked
	// every PeerEvictInterval (<= 0 does not check).
	PeerIdleTimeout   time.Duration
	PeerEvictInterval time.Duration
	// How long a refused key is not asked about again, the rate and burst
	// of miss handler calls, and the longest a handshake worker waits for
	// one (see userwireguard PeerMissSettings).
	PeerMissNegativeTtl    time.Duration
	PeerMissRatePerSecond  float64
	PeerMissBurst          int
	PeerMissHandlerTimeout time.Duration
}

// implements wg device:
//   - parses packets from wg by source ip to forward to tun
//   - all packets from tuns are put back into wg
//     the wg proxy reader is activated on first sent packet from the proxy
type WgProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	settings *WgProxySettings
	log      connect.Logger

	events  chan uwgtun.Event
	receive chan []byte
	// Event sends finish or observe cancellation before the tun closes events.
	// This lock is independent of every packet and client-map operation.
	eventsLock   sync.RWMutex
	eventsClosed bool

	device *device.Device

	// controlLock serializes control-plane operations (AddClients / RemoveClients
	// / SetClients) against each other and is held across device.IpcSet. It is
	// NEVER taken by the data path, so programming peers does not block packet
	// forwarding.
	controlLock sync.Mutex

	// stateLock guards the client maps below. It is held only for brief map
	// reads/writes — never across device.IpcSet (see controlLock) or across a
	// client.Tun() device creation — so the per-packet data path is not
	// serialized behind slow control-plane or device-setup work.
	stateLock sync.RWMutex

	clients map[netip.Addr]*WgClient
	// when each client's config was last applied to the device,
	// used as a removal grace cutoff by `RemoveClients`
	clientAddTimes map[netip.Addr]time.Time
	activeClients  map[netip.Addr]WgTun
	// Activity advances under the map lock without taking an exclusive lock
	// on the packet fast path. Eviction may detach only an unchanged snapshot.
	activeClientActivities map[netip.Addr]*atomic.Uint64
	// Reverse membership avoids scanning all clients when a tun moves.
	activeTunAddrs map[WgTun]map[netip.Addr]struct{}
	// the configured client of each key: what the miss handler answers
	// from, and how a live peer is named
	clientKeys map[device.NoisePublicKey]*wgClientKey

	evictedPeerCount atomic.Uint64

	closeActiveClientsOnce sync.Once
}

// WgRuntimeStats is process-local receive health without peer identity. The
// values are cumulative for one WireGuard device generation.
type WgRuntimeStats struct {
	InboundPeerQueueDropPacketCount       uint64
	InboundDecryptionQueueDropPacketCount uint64
	ReceiveRoutineFailureCount            uint64
}

// WgPeerStats is the device's peer population and, with on-demand peers, the
// outcomes of the initiations that created and removed them. The counts are
// cumulative for one WireGuard device generation.
type WgPeerStats struct {
	// peers on the device now
	PeerCount int
	// initiations from keys without a peer (userwireguard PeerMissStats)
	PeerMiss device.PeerMissStats
	// peers removed for idleness
	EvictedPeerCount uint64
}

// One configured client's peer configuration, keyed by its public key.
type wgClientKey struct {
	addr         netip.Addr
	presharedKey *device.NoisePresharedKey
}

// Returns the indexed handshake secret and allowed address.
func (self *wgClientKey) peerMissConfig() device.PeerMissConfig {
	return device.PeerMissConfig{
		PresharedKey: self.presharedKey,
		AllowedIPs:   []netip.Prefix{netip.PrefixFrom(self.addr, 32)},
	}
}

// Compares the configuration that a live peer was created with.
func (self *wgClientKey) matches(other *wgClientKey) bool {
	if self.addr != other.addr {
		return false
	}
	var presharedKey, otherPresharedKey device.NoisePresharedKey
	if self.presharedKey != nil {
		presharedKey = *self.presharedKey
	}
	if other.presharedKey != nil {
		otherPresharedKey = *other.presharedKey
	}
	return presharedKey == otherPresharedKey
}

// Copies the validated identity and handshake configuration into the index.
func newWgClientKey(entry *wgPeerEntry) (device.NoisePublicKey, *wgClientKey) {
	clientKey := &wgClientKey{addr: entry.addr}
	if entry.peerConfig.PresharedKey != nil {
		presharedKey := device.NoisePresharedKey(*entry.peerConfig.PresharedKey)
		clientKey.presharedKey = &presharedKey
	}
	return device.NoisePublicKey(entry.peerConfig.PublicKey), clientKey
}

type wgTunDevice struct {
	proxy *WgProxy
}

func (self *wgTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return self.proxy.Read(bufs, sizes, offset)
}

func (self *wgTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	return self.proxy.Write(bufs, offset)
}

func (self *wgTunDevice) MTU() int {
	return self.proxy.MTU()
}

func (self *wgTunDevice) Events() <-chan uwgtun.Event {
	return self.proxy.Events()
}

func (self *wgTunDevice) AddEvent(event uwgtun.Event) {
	self.proxy.AddEvent(event)
}

// The tun owns the event channel; closing it releases WireGuard's event reader.
// Cancel first so a sender blocked on a full channel can release its read lock.
func (self *wgTunDevice) Close() error {
	self.proxy.cancel()
	self.proxy.eventsLock.Lock()
	defer self.proxy.eventsLock.Unlock()
	if !self.proxy.eventsClosed {
		self.proxy.eventsClosed = true
		close(self.proxy.events)
	}
	return nil
}

func (self *wgTunDevice) BatchSize() int {
	return self.proxy.BatchSize()
}

func NewWgProxyWithDefaults(ctx context.Context) *WgProxy {
	return NewWgProxy(ctx, DefaultWgProxySettings())
}

func NewWgProxy(ctx context.Context, settings *WgProxySettings) *WgProxy {
	cancelCtx, cancel := context.WithCancel(ctx)

	log := settings.Log
	if log == nil {
		log = connect.DefaultLogger()
	}

	wg := &WgProxy{
		ctx:            cancelCtx,
		cancel:         cancel,
		settings:       settings,
		log:            log,
		events:         make(chan uwgtun.Event, settings.EventsSequenceSize),
		receive:        make(chan []byte, settings.ReceiveSequenceSize),
		clients:        map[netip.Addr]*WgClient{},
		clientAddTimes: map[netip.Addr]time.Time{},
		activeClients:  map[netip.Addr]WgTun{},
		clientKeys:     map[device.NoisePublicKey]*wgClientKey{},
	}

	logger := &logger.Logger{
		Verbosef: func(format string, args ...any) {
			log.Infof("[wg]"+format, args...)
		},
		Errorf: func(format string, args ...any) {
			log.Errorf("[wg]"+format, args...)
		},
	}
	wg.device = device.NewDevice(&wgTunDevice{proxy: wg}, conn.NewDefaultBind(), logger)

	if settings.PeersOnDemand {
		missSettings := device.DefaultPeerMissSettings()
		missSettings.Handler = wg.peerMiss
		missSettings.NegativeTtl = settings.PeerMissNegativeTtl
		missSettings.RatePerSecond = settings.PeerMissRatePerSecond
		missSettings.Burst = settings.PeerMissBurst
		missSettings.HandlerTimeout = settings.PeerMissHandlerTimeout
		wg.device.SetPeerMissSettings(missSettings)
		if 0 < settings.PeerEvictInterval && 0 < settings.PeerIdleTimeout {
			go connect.HandleError(wg.runPeerEviction)
		}
	}

	// go connect.HandleError(wg.run)

	return wg
}

// func (self *WgProxy) run() {
// 	defer self.closeActiveClients()
// 	defer self.cancel()
// 	for {
// 		func() {
// 			self.stateLock.Lock()
// 			defer self.stateLock.Unlock()

// 			for addr, activeTun := range self.activeClients {
// 				if activeTun.CancelIfIdle() {
// 					activeTun.SetReceive(nil)
// 					delete(self.activeClients, addr)
// 				}
// 			}
// 		}()

// 		select {
// 		case <-self.ctx.Done():
// 			return
// 		case <-time.After(self.settings.CheckTunIdleTimeout):
// 		}
// 	}
// }

func (self *WgProxy) ListenAndServe(ipv4 string, ipv6 string, port int) error {
	defer self.cancel()

	privateKey, err := wgtypes.ParseKey(self.settings.PrivateKey)
	if err != nil {
		return err
	}

	self.log.Infof("[wg]ipv4=%s ipv6=%s port=%d fwmark=%d\n", ipv4, ipv6, port, self.settings.FirewallMark)
	// ReplacePeers must be false: this initial device config races with
	// AddClients at startup (e.g. the proxy client restore after a restart),
	// and a wipe here would silently drop any peers that won the race
	config := &device.Config{
		Config: wgtypes.Config{
			PrivateKey:   &privateKey,
			ListenPort:   &port,
			ReplacePeers: false,
			Peers:        []wgtypes.PeerConfig{},
		},
		BindIpv4: &ipv4,
		BindIpv6: &ipv6,
	}
	if 0 < self.settings.FirewallMark {
		config.FirewallMark = &self.settings.FirewallMark
	}

	err = self.device.IpcSet2(config)
	if err != nil {
		return err
	}

	self.device.AddEvent(uwgtun.EventUp)

	select {
	case <-self.device.Wait():
	case <-self.ctx.Done():
		self.device.Close()
	}
	return nil
}

// hot patches the devices into the wg server
// if the device is already active, keep it active
func (self *WgProxy) SetClients(clients map[netip.Addr]*WgClient) (returnErr error) {
	self.controlLock.Lock()
	defer self.controlLock.Unlock()

	if self.settings.PeersOnDemand {
		entries, err := createPeerEntries(clients)
		returnErr = err
		clientAddrs := make(map[netip.Addr]bool, len(entries))
		for _, entry := range entries {
			clientAddrs[entry.addr] = true
		}
		removedAddrs := []netip.Addr{}
		func() {
			self.stateLock.RLock()
			defer self.stateLock.RUnlock()
			for addr := range self.clients {
				if !clientAddrs[addr] {
					removedAddrs = append(removedAddrs, addr)
				}
			}
		}()
		// Remove old generations before publishing or seeding replacements.
		returnErr = errors.Join(returnErr, self.removeClientsWithLock(nil, removedAddrs...))
		returnErr = errors.Join(returnErr, self.indexClientsWithLock(entries, map[netip.Addr]*WgClient{}))
	} else {
		// wipe all peers, then re-apply the given clients in batches. IpcSet runs
		// outside stateLock (the device is internally synchronized) so the data path
		// is not blocked while peers are reprogrammed.
		wipeConfig := wgtypes.Config{
			ReplacePeers: true,
			Peers:        []wgtypes.PeerConfig{},
		}
		if err := self.device.IpcSet(&wipeConfig); err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			clear(self.clients)
			clear(self.clientAddTimes)
			clear(self.clientKeys)
		}()

		_, returnErr = self.addClientsWithLock(clients)
	}

	// reconcile the active tuns against the new client set: drop tuns whose
	// client was removed, and swap a tun that no longer matches its client's
	// tun. Snapshot under the lock, but call client.Tun() (which may create a
	// device) outside it.
	type activeEntry struct {
		addr      netip.Addr
		activeTun WgTun
		client    *WgClient
	}
	var actives []activeEntry
	func() {
		self.stateLock.RLock()
		defer self.stateLock.RUnlock()
		for addr, activeTun := range self.activeClients {
			actives = append(actives, activeEntry{addr: addr, activeTun: activeTun, client: self.clients[addr]})
		}
	}()
	for _, a := range actives {
		if a.client == nil {
			self.removeActiveClient(a.addr, a.activeTun)
			self.syncTunReceive(a.activeTun, a.addr)
			a.activeTun.Cancel()
			continue
		}
		tun, err := a.client.Tun()
		if err != nil {
			self.removeActiveClient(a.addr, a.activeTun)
			self.syncTunReceive(a.activeTun, a.addr)
			a.activeTun.Cancel()
			returnErr = errors.Join(returnErr, err)
			continue
		}
		if tun != a.activeTun {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.setActiveClientWithLock(a.addr, tun)
			}()
			self.syncTunReceive(a.activeTun, a.addr)
			a.activeTun.Cancel()
			self.syncTunReceive(tun, a.addr)
		}
	}

	return
}

// removeActiveClient drops the active tun for addr, but only if it is still the
// registered one (a concurrent activation may have replaced it).
func (self *WgProxy) removeActiveClient(addr netip.Addr, activeTun WgTun) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.activeClients[addr] == activeTun {
		self.forgetActiveClientWithLock(addr)
	}
}

// Forgets one attachment and its reverse membership while the state lock is held.
func (self *WgProxy) forgetActiveClientWithLock(addr netip.Addr) {
	tun := self.activeClients[addr]
	if addrs := self.activeTunAddrs[tun]; addrs != nil {
		delete(addrs, addr)
		if len(addrs) == 0 {
			delete(self.activeTunAddrs, tun)
		}
	}
	delete(self.activeClients, addr)
	delete(self.activeClientActivities, addr)
}

// Publishes a tun and records activity while the state lock is held.
func (self *WgProxy) setActiveClientWithLock(addr netip.Addr, tun WgTun) {
	if self.activeClients[addr] != tun {
		self.forgetActiveClientWithLock(addr)
	}
	if self.activeClientActivities == nil {
		self.activeClientActivities = map[netip.Addr]*atomic.Uint64{}
	}
	activity := self.activeClientActivities[addr]
	if activity == nil || self.activeClients[addr] != tun {
		activity = &atomic.Uint64{}
		self.activeClientActivities[addr] = activity
	}
	self.activeClients[addr] = tun
	if self.activeTunAddrs == nil {
		self.activeTunAddrs = map[WgTun]map[netip.Addr]struct{}{}
	}
	if self.activeTunAddrs[tun] == nil {
		self.activeTunAddrs[tun] = map[netip.Addr]struct{}{}
	}
	self.activeTunAddrs[tun][addr] = struct{}{}
	activity.Add(1)
}

// AddClients applies the given clients to the device without replacing existing
// peers (ReplacePeers:false). It is idempotent: re-applying an already
// registered client is a no-op/update, and a client that was dropped on a
// previous call (e.g. a transient validation failure) is retried here rather
// than being stranded as "known". Peers are applied in batches of
// `ClientBatchSize`; a failed batch is retried per peer so that one bad peer
// cannot drop the rest (e.g. during the full restore at instance startup).
// The returned map contains exactly the clients whose peer config was applied
// to the device in this call; per-client failures are joined into the error.
func (self *WgProxy) AddClients(clients map[netip.Addr]*WgClient) (map[netip.Addr]*WgClient, error) {
	self.controlLock.Lock()
	defer self.controlLock.Unlock()
	return self.addClientsWithLock(clients)
}

// Programs the given clients' peers into the device and records them.
// The caller must hold controlLock (serializing control-plane device writes).
// device.IpcSet runs WITHOUT stateLock; stateLock is taken only to record each
// batch right after it is programmed, minimizing the window where a peer exists
// in the device but is not yet routable via activateClient.
func (self *WgProxy) addClientsWithLock(clients map[netip.Addr]*WgClient) (applied map[netip.Addr]*WgClient, returnErr error) {
	applied = map[netip.Addr]*WgClient{}
	if len(clients) == 0 {
		return
	}

	// createPeerEntries is best-effort: invalid clients are skipped and joined
	// into the error, but the valid peers are still applied.
	entries, returnErr := createPeerEntries(clients)

	if self.settings.PeersOnDemand {
		returnErr = errors.Join(returnErr, self.indexClientsWithLock(entries, applied))
		return
	}

	batchSize := self.settings.ClientBatchSize
	if batchSize <= 0 {
		batchSize = len(entries)
	}

	record := func(batch []*wgPeerEntry) {
		now := time.Now()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range batch {
			if previous := self.clients[entry.addr]; previous != nil && previous.PublicKey != entry.client.PublicKey {
				if previousKey, err := wgtypes.ParseKey(previous.PublicKey); err == nil {
					delete(self.clientKeys, device.NoisePublicKey(previousKey))
				}
			}
			self.clients[entry.addr] = entry.client
			self.clientAddTimes[entry.addr] = now
			key, clientKey := newWgClientKey(entry)
			self.clientKeys[key] = clientKey
			applied[entry.addr] = entry.client
		}
	}

	for start := 0; start < len(entries); start += batchSize {
		batch := entries[start:min(start+batchSize, len(entries))]
		peers := make([]wgtypes.PeerConfig, 0, len(batch))
		for _, entry := range batch {
			peers = append(peers, entry.peerConfig)
		}
		config := wgtypes.Config{
			ReplacePeers: false,
			Peers:        peers,
		}
		if err := self.device.IpcSet(&config); err == nil {
			record(batch)
		} else {
			// the device applies peers in order and stops at the first error,
			// so retry each peer individually to apply the rest of the batch
			for _, entry := range batch {
				config := wgtypes.Config{
					ReplacePeers: false,
					Peers:        []wgtypes.PeerConfig{entry.peerConfig},
				}
				if err := self.device.IpcSet(&config); err == nil {
					record([]*wgPeerEntry{entry})
				} else {
					returnErr = errors.Join(returnErr, fmt.Errorf("add client %s: %w", entry.addr, err))
				}
			}
		}
	}

	if count := self.ClientCount(); (device.MaxPeers*9)/10 <= count {
		self.log.Warningf("[wg]peer count %d is near the device limit %d\n", count, device.MaxPeers)
	}

	return
}

// Records on-demand clients without creating device peers; the
// device asks peerMiss for a client's configuration at its first initiation.
// The caller must hold controlLock.
//
// Index changes that invalidate a live peer remove it, and its client's next
// initiation recreates it from the index: an address that now has another
// key drops the old key, and a key that moved to another address drops the
// old address. A changed preshared key drops the previous peer as well.
// Endpoint-bearing clients are seeded after removal, for server-first traffic.
// New and changed keys invalidate pending answers and remembered refusals.
func (self *WgProxy) indexClientsWithLock(entries []*wgPeerEntry, applied map[netip.Addr]*WgClient) (returnErr error) {
	type seed struct {
		key       device.NoisePublicKey
		clientKey *wgClientKey
		endpoint  *net.UDPAddr
	}
	type detach struct {
		addr netip.Addr
		tun  WgTun
	}
	staleKeys := map[device.NoisePublicKey]bool{}
	staleAddrs := map[netip.Addr]bool{}
	detaches := []detach{}
	seeds := []seed{}
	changedKeys := []device.NoisePublicKey{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// Compare the whole batch with the old index before changing it, so
		// address swaps cannot remove another entry from the same batch.
		for _, entry := range entries {
			key, clientKey := newWgClientKey(entry)
			if previous, ok := self.clients[entry.addr]; ok && previous.PublicKey != entry.client.PublicKey {
				if previousKey, err := wgtypes.ParseKey(previous.PublicKey); err == nil {
					staleKeys[device.NoisePublicKey(previousKey)] = true
				}
				staleAddrs[entry.addr] = true
			}
			if previous, ok := self.clientKeys[key]; !ok {
				changedKeys = append(changedKeys, key)
			} else if !previous.matches(clientKey) {
				staleKeys[key] = true
				staleAddrs[previous.addr] = true
				changedKeys = append(changedKeys, key)
			}
		}
		for key := range staleKeys {
			delete(self.clientKeys, key)
		}
		for addr := range staleAddrs {
			delete(self.clients, addr)
			delete(self.clientAddTimes, addr)
			if tun, ok := self.activeClients[addr]; ok {
				detaches = append(detaches, detach{addr: addr, tun: tun})
				self.forgetActiveClientWithLock(addr)
			}
		}
	}()

	// Stop old peers, joining their packet writers, before a replacement
	// client can be selected by the same source address.
	for key := range staleKeys {
		self.device.RemovePeer(key)
	}
	for _, d := range detaches {
		self.syncTunReceive(d.tun, d.addr)
	}
	func() {
		now := time.Now()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range entries {
			key, clientKey := newWgClientKey(entry)
			self.clients[entry.addr] = entry.client
			self.clientAddTimes[entry.addr] = now
			self.clientKeys[key] = clientKey
			applied[entry.addr] = entry.client
			if entry.client.Endpoint != nil {
				seeds = append(seeds, seed{key: key, clientKey: clientKey, endpoint: entry.client.Endpoint})
			}
		}
	}()

	for _, key := range changedKeys {
		self.device.ClearPeerMissRefusal(key)
	}
	if 0 < len(seeds) {
		endpointPeers := make([]wgtypes.PeerConfig, 0, len(seeds))
		for _, seed := range seeds {
			if _, err := self.device.AddPeerOnDemand(seed.key, seed.clientKey.peerMissConfig()); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("add client %s: %w", seed.clientKey.addr, err))
				continue
			}
			endpointPeers = append(endpointPeers, wgtypes.PeerConfig{
				PublicKey:  wgtypes.Key(seed.key),
				UpdateOnly: true,
				Endpoint:   seed.endpoint,
			})
		}
		if 0 < len(endpointPeers) {
			if err := self.device.IpcSet(&wgtypes.Config{Peers: endpointPeers}); err != nil {
				returnErr = errors.Join(returnErr, err)
			}
		}
	}
	if count := self.device.PeerCount(); (device.MaxPeers*9)/10 <= count {
		self.log.Warningf("[wg]peer count %d is near the device limit %d\n", count, device.MaxPeers)
	}
	return
}

// Clients returns the registered client addresses with the time each client's
// config was last applied.
func (self *WgProxy) Clients() map[netip.Addr]time.Time {
	self.stateLock.RLock()
	defer self.stateLock.RUnlock()
	return maps.Clone(self.clientAddTimes)
}

func (self *WgProxy) ClientCount() int {
	self.stateLock.RLock()
	defer self.stateLock.RUnlock()
	return len(self.clients)
}

// RuntimeStats exposes the shared UDP receive boundary for server metrics.
func (self *WgProxy) RuntimeStats() WgRuntimeStats {
	return WgRuntimeStats{
		InboundPeerQueueDropPacketCount:       self.device.InboundPeerQueueDropPacketCount(),
		InboundDecryptionQueueDropPacketCount: self.device.InboundDecryptionQueueDropPacketCount(),
		ReceiveRoutineFailureCount:            self.device.ReceiveRoutineFailureCount(),
	}
}

func (self *WgProxy) PeerStats() WgPeerStats {
	return WgPeerStats{
		PeerCount:        self.device.PeerCount(),
		PeerMiss:         self.device.PeerMissStats(),
		EvictedPeerCount: self.evictedPeerCount.Load(),
	}
}

// PeerCount is the number of peers on the device. With on-demand peers it
// is the clients that handshook recently, not the configured clients
// (ClientCount).
func (self *WgProxy) PeerCount() int {
	return self.device.PeerCount()
}

// peerMiss is the device's miss handler: it answers from the client index in
// memory, so a handshake worker never waits on I/O. A key is accepted exactly
// when AddClients registered it and RemoveClients has not removed it.
func (self *WgProxy) peerMiss(publicKey device.NoisePublicKey) (device.PeerMissConfig, bool) {
	self.stateLock.RLock()
	clientKey, ok := self.clientKeys[publicKey]
	self.stateLock.RUnlock()
	if !ok {
		return device.PeerMissConfig{}, false
	}
	return clientKey.peerMissConfig(), true
}

func (self *WgProxy) runPeerEviction() {
	ticker := time.NewTicker(self.settings.PeerEvictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-ticker.C:
		}
		self.evictIdlePeers(self.settings.PeerIdleTimeout)
	}
}

// evictIdlePeers removes the peers with no handshake within idle and detaches
// their clients' tuns, and returns how many it removed. The clients stay
// configured: the next initiation from one recreates its peer.
func (self *WgProxy) evictIdlePeers(idle time.Duration) int {
	activities := self.snapshotClientActivities()
	removed := self.device.RemoveIdlePeers(idle)
	if len(removed) == 0 {
		return 0
	}
	self.evictedPeerCount.Add(uint64(len(removed)))
	self.detachKeys(removed, activities)
	return len(removed)
}

// Captures the attachment and its activity before a peer-removal pass.
type wgClientActivity struct {
	publicKey string
	tun       WgTun
	activity  *atomic.Uint64
	count     uint64
}

// Records only active clients; new packets advance their counters atomically.
func (self *WgProxy) snapshotClientActivities() map[netip.Addr]wgClientActivity {
	self.stateLock.RLock()
	defer self.stateLock.RUnlock()
	activities := make(map[netip.Addr]wgClientActivity, len(self.activeClients))
	for addr, tun := range self.activeClients {
		client := self.clients[addr]
		activity := self.activeClientActivities[addr]
		if client != nil && activity != nil {
			activities[addr] = wgClientActivity{
				publicKey: client.PublicKey,
				tun:       tun,
				activity:  activity,
				count:     activity.Load(),
			}
		}
	}
	return activities
}

// Detaches unchanged active tuns of the given keys' clients from the
// wg receive channel. A tun stays open: the hosted device has its own
// lifetime, and the client's next packet attaches it again.
func (self *WgProxy) detachKeys(keys []device.NoisePublicKey, activities map[netip.Addr]wgClientActivity) {
	type detach struct {
		addr netip.Addr
		tun  WgTun
	}
	detaches := []detach{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, key := range keys {
			clientKey, ok := self.clientKeys[key]
			if !ok {
				continue
			}
			previous, ok := activities[clientKey.addr]
			activity := self.activeClientActivities[clientKey.addr]
			if !ok || previous.publicKey != wgtypes.Key(key).String() ||
				activity != previous.activity || activity.Load() != previous.count ||
				self.activeClients[clientKey.addr] != previous.tun {
				continue
			}
			if tun, ok := self.activeClients[clientKey.addr]; ok {
				detaches = append(detaches, detach{addr: clientKey.addr, tun: tun})
				self.forgetActiveClientWithLock(clientKey.addr)
			}
		}
	}()
	for _, d := range detaches {
		self.syncTunReceive(d.tun, d.addr)
	}
}

// WgPeerStatus is a registered client's live peer session facts: the endpoint
// the device has learned (or was seeded with) and the last completed
// handshake. This is the export side of the deploy endpoint handoff
// (PROXYDRAIN1.md §3.4).
type WgPeerStatus struct {
	ClientIpv4 netip.Addr
	PublicKey  string
	// Endpoint is the peer's current endpoint; nil when the device has never
	// seen (or been seeded with) one.
	Endpoint *net.UDPAddr
	// LastHandshake is zero when the peer has never completed a handshake.
	LastHandshake time.Time
}

// PeerStatuses reports the live peer status for every registered client
// that has a device peer, keyed by client ipv4. Clients whose peer the device
// does not report (e.g. registered concurrently with the read, or with no
// on-demand peer) are omitted. It reads the device's peer snapshots, so its
// cost follows the device peers, not the configured clients.
func (self *WgProxy) PeerStatuses() (map[netip.Addr]*WgPeerStatus, error) {
	snapshots := self.device.PeerSnapshots()

	self.stateLock.RLock()
	defer self.stateLock.RUnlock()
	peerStatuses := make(map[netip.Addr]*WgPeerStatus, len(snapshots))
	for _, snapshot := range snapshots {
		clientKey, ok := self.clientKeys[snapshot.PublicKey]
		if !ok {
			continue
		}
		peerStatus := &WgPeerStatus{
			ClientIpv4:    clientKey.addr,
			PublicKey:     wgtypes.Key(snapshot.PublicKey).String(),
			LastHandshake: snapshot.LastHandshake,
		}
		if snapshot.Endpoint.IsValid() {
			peerStatus.Endpoint = net.UDPAddrFromAddrPort(snapshot.Endpoint)
		}
		peerStatuses[clientKey.addr] = peerStatus
	}
	return peerStatuses, nil
}

// SeedEndpoints sets the endpoint on the peers of already registered
// clients (UpdateOnly: an endpoint for an unregistered client is skipped,
// never creating a peer). With on-demand peers a registered client's peer is
// created first, since the server reaches it before it handshakes. Returns
// the number of endpoints applied. This is the replacement instance's
// endpoint restore in the deploy handoff (PROXYDRAIN1.md §3.4); pair with
// `InitiateHandshake`.
func (self *WgProxy) SeedEndpoints(endpoints map[netip.Addr]*net.UDPAddr) (int, error) {
	self.controlLock.Lock()
	defer self.controlLock.Unlock()

	type seed struct {
		key       device.NoisePublicKey
		clientKey *wgClientKey
		endpoint  *net.UDPAddr
	}
	seeds := []seed{}
	func() {
		self.stateLock.RLock()
		defer self.stateLock.RUnlock()
		for addr, endpoint := range endpoints {
			if endpoint == nil {
				continue
			}
			client, ok := self.clients[addr]
			if !ok {
				continue
			}
			publicKey, err := wgtypes.ParseKey(client.PublicKey)
			if err != nil {
				continue
			}
			key := device.NoisePublicKey(publicKey)
			clientKey, ok := self.clientKeys[key]
			if !ok {
				continue
			}
			seeds = append(seeds, seed{key: key, clientKey: clientKey, endpoint: endpoint})
		}
	}()

	var returnErr error
	peers := []wgtypes.PeerConfig{}
	for _, seed := range seeds {
		if self.settings.PeersOnDemand {
			if _, err := self.device.AddPeerOnDemand(seed.key, seed.clientKey.peerMissConfig()); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("seed client %s: %w", seed.clientKey.addr, err))
				continue
			}
		}
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:  wgtypes.Key(seed.key),
			UpdateOnly: true,
			Endpoint:   seed.endpoint,
		})
	}
	if len(peers) == 0 {
		return 0, returnErr
	}

	config := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}
	if err := self.device.IpcSet(&config); err != nil {
		return 0, errors.Join(returnErr, err)
	}
	return len(peers), returnErr
}

// InitiateHandshake sends a handshake initiation to the client's peer. The
// peer must have an endpoint (seeded via `WgClient.Endpoint` or learned from
// a packet) for the initiation to be sendable. One call is enough: the device
// arms its own handshake retry timers (RekeyTimeout pace, RekeyAttemptTime
// bound), and repeated calls are internally rate limited.
//
// This is the replacement instance's half of the deploy endpoint handoff
// (PROXYDRAIN1.md §3.4): initiations sent before the deploy's conntrack flush
// are harmlessly blackholed (the client's reply still DNATs to the old
// instance); the retry that lands after the flush re-establishes the session
// in ~1 RTT, instead of waiting out the client's dead-session timers.
func (self *WgProxy) InitiateHandshake(addr netip.Addr) error {
	self.controlLock.Lock()
	defer self.controlLock.Unlock()

	client := func() *WgClient {
		self.stateLock.RLock()
		defer self.stateLock.RUnlock()
		return self.clients[addr]
	}()
	if client == nil {
		return fmt.Errorf("no client for %s", addr)
	}
	publicKey, err := wgtypes.ParseKey(client.PublicKey)
	if err != nil {
		return fmt.Errorf("parse public key for %s: %w", addr, err)
	}
	key := device.NoisePublicKey(publicKey)
	peer := self.device.LookupPeer(key)
	if peer == nil && self.settings.PeersOnDemand {
		// the server reaches the client first: create its peer, as the
		// client's own initiation would
		clientKey := func() *wgClientKey {
			self.stateLock.RLock()
			defer self.stateLock.RUnlock()
			return self.clientKeys[key]
		}()
		if clientKey != nil {
			peer, err = self.device.AddPeerOnDemand(key, clientKey.peerMissConfig())
			if err != nil {
				return fmt.Errorf("create peer for %s: %w", addr, err)
			}
		}
	}
	if peer == nil {
		return fmt.Errorf("no peer for %s", addr)
	}
	return peer.SendHandshakeInitiation(false)
}

// RemoveClients removes the peers for the given addresses from the device and
// forgets the clients. Only clients whose config was last applied before
// `addedBefore` are removed: a reconcile pass computes removals from a db
// snapshot, and the cutoff makes a client applied concurrently with the
// snapshot (e.g. by a warmup call) immune until the next pass.
func (self *WgProxy) RemoveClients(addedBefore time.Time, addrs ...netip.Addr) (returnErr error) {
	self.controlLock.Lock()
	defer self.controlLock.Unlock()
	return self.removeClientsWithLock(&addedBefore, addrs...)
}

// Removes registered clients while the control lock is held. A nil cutoff
// removes them regardless of their last configuration time.
func (self *WgProxy) removeClientsWithLock(addedBefore *time.Time, addrs ...netip.Addr) (returnErr error) {
	// decide removal eligibility under the lock, then program the device outside it
	type removal struct {
		addr       netip.Addr
		peerConfig wgtypes.PeerConfig
	}
	var removals []removal
	func() {
		self.stateLock.RLock()
		defer self.stateLock.RUnlock()
		for _, addr := range addrs {
			client, ok := self.clients[addr]
			if !ok {
				continue
			}
			if addTime, ok := self.clientAddTimes[addr]; addedBefore != nil && ok && !addTime.Before(*addedBefore) {
				// applied at or after the cutoff: keep (grace window)
				continue
			}
			publicKey, err := wgtypes.ParseKey(client.PublicKey)
			if err != nil {
				// the key parsed when the client was applied, so this is unexpected
				returnErr = errors.Join(returnErr, fmt.Errorf("remove client %s: %w", addr, err))
				continue
			}
			removals = append(removals, removal{
				addr: addr,
				peerConfig: wgtypes.PeerConfig{
					PublicKey:  publicKey,
					Remove:     true,
					UpdateOnly: true,
				},
			})
		}
	}()
	if len(removals) == 0 {
		return
	}

	// forget the clients whose peers were removed, capturing any active tuns to
	// tear down once the lock is released
	type activeTunRemoval struct {
		addr netip.Addr
		tun  WgTun
	}
	var activeTuns []activeTunRemoval
	forget := func(batch []removal) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range batch {
			delete(self.clients, entry.addr)
			delete(self.clientAddTimes, entry.addr)
			key := device.NoisePublicKey(entry.peerConfig.PublicKey)
			if clientKey, ok := self.clientKeys[key]; ok && clientKey.addr == entry.addr {
				delete(self.clientKeys, key)
			}
			if t, ok := self.activeClients[entry.addr]; ok {
				activeTuns = append(activeTuns, activeTunRemoval{addr: entry.addr, tun: t})
				self.forgetActiveClientWithLock(entry.addr)
			}
		}
	}

	if self.settings.PeersOnDemand {
		// unindex first, so the miss handler refuses the keys, then remove
		// whatever live peers they have
		forget(removals)
		for _, entry := range removals {
			self.device.RemovePeer(device.NoisePublicKey(entry.peerConfig.PublicKey))
		}
		for _, activeTun := range activeTuns {
			self.syncTunReceive(activeTun.tun, activeTun.addr)
			activeTun.tun.Cancel()
		}
		return
	}

	batchSize := self.settings.ClientBatchSize
	if batchSize <= 0 {
		batchSize = len(removals)
	}

	// peers are removed in batches, mirroring client registration. One device transaction
	// per peer would hold controlLock across thousands of serial IpcSet calls when
	// a reconcile pass drops a large stale set, stalling every concurrent
	// AddClients (a new client's first connection) behind it.
	for start := 0; start < len(removals); start += batchSize {
		batch := removals[start:min(start+batchSize, len(removals))]
		peers := make([]wgtypes.PeerConfig, 0, len(batch))
		for _, entry := range batch {
			peers = append(peers, entry.peerConfig)
		}
		// program the device outside stateLock (the device is internally
		// synchronized) so the data path is not blocked while peers are removed
		config := wgtypes.Config{Peers: peers}
		if err := self.device.IpcSet(&config); err == nil {
			forget(batch)
		} else {
			// the device applies peers in order and stops at the first error,
			// so retry each peer individually to remove the rest of the batch
			for _, entry := range batch {
				config := wgtypes.Config{Peers: []wgtypes.PeerConfig{entry.peerConfig}}
				if err := self.device.IpcSet(&config); err == nil {
					forget([]removal{entry})
				} else {
					returnErr = errors.Join(returnErr, fmt.Errorf("remove client %s: %w", entry.addr, err))
				}
			}
		}
	}

	for _, activeTun := range activeTuns {
		self.syncTunReceive(activeTun.tun, activeTun.addr)
		activeTun.tun.Cancel()
	}
	return
}

// activateClient returns the tun for the client at addr, creating or
// reactivating it as needed. It is on the per-packet wg ingress path (Write), so
// the fast path — an already-active, live tun — takes only a brief read lock and
// runs the liveness check and receive-mode re-assert with NO lock held across the
// per-device calls. This keeps wg ingress for all clients from serializing on one
// global mutex.
func (self *WgProxy) activateClient(addr netip.Addr) (WgTun, error) {
	self.stateLock.RLock()
	tun := self.activeClients[addr]
	if activity := self.activeClientActivities[addr]; activity != nil {
		activity.Add(1)
	}
	self.stateLock.RUnlock()
	if tun != nil && tun.Active() && tun.UpdateActivity() {
		// Re-assert the address attachment on each call. Address-aware devices keep
		// Tun traffic independent; legacy implementations may still use a global
		// mode. Both attachment forms are idempotent in the common case.
		self.syncTunReceive(tun, addr)
		return tun, nil
	}
	return self.activateClientSlow(addr)
}

// activateClientSlow handles the miss/dead case: it creates the device via
// client.Tun() WITHOUT holding the state lock (it may do db + device + tun
// setup). OpenProxyDevice dedups per proxy id and owns the recreate-on-death
// logic, so concurrent first packets converge on one device and a dead tun is
// transparently replaced.
func (self *WgProxy) activateClientSlow(addr netip.Addr) (WgTun, error) {
	self.stateLock.RLock()
	client, ok := self.clients[addr]
	self.stateLock.RUnlock()
	if !ok {
		return nil, fmt.Errorf("No client found for %s.", addr)
	}

	tun, err := client.Tun()
	if err != nil {
		return nil, err
	}
	tun.UpdateActivity()

	self.stateLock.Lock()
	// the client may have been removed while the device was being created
	// (RemoveClients deletes clients[addr] under this lock); if so, do not
	// publish a tun for it
	if _, stillClient := self.clients[addr]; !stillClient {
		self.stateLock.Unlock()
		self.syncTunReceive(tun, addr)
		tun.Cancel()
		return nil, fmt.Errorf("No client found for %s.", addr)
	}
	self.setActiveClientWithLock(addr, tun)
	self.stateLock.Unlock()
	self.syncTunReceive(tun, addr)
	return tun, nil
}

func (self *WgProxy) MTU() int {
	return 0
}

func (self *WgProxy) Events() <-chan uwgtun.Event {
	return self.events
}

// Retains event ownership until admission or cancellation. The close guard
// prevents a select from choosing a send on the already-closed channel.
func (self *WgProxy) AddEvent(event uwgtun.Event) {
	self.eventsLock.RLock()
	defer self.eventsLock.RUnlock()
	if self.eventsClosed || self.ctx.Err() != nil {
		return
	}
	select {
	case <-self.ctx.Done():
	case self.events <- event:
	}
}

func (self *WgProxy) BatchSize() int {
	return max(self.uploadPacketBatchSize(), self.downloadPacketBatchSize())
}

// Resolves the measured directional default to at least one packet.
func (self *WgProxy) uploadPacketBatchSize() int {
	return max(1, self.settings.UploadPacketBatchSize)
}

// Resolves the measured directional default to at least one packet.
func (self *WgProxy) downloadPacketBatchSize() int {
	return max(1, self.settings.DownloadPacketBatchSize)
}

// `uwgtun.Device` implementation
func (self *WgProxy) Write(bufs [][]byte, offset int) (count int, returnErr error) {
	if len(bufs) == 0 {
		return
	}
	firstSourceAddr := netip.Addr{}
	homogeneousSource := true
	for _, buf := range bufs {
		if len(buf) < offset {
			homogeneousSource = false
			break
		}
		ipPath, err := connect.ParseIpPath(buf[offset:])
		if err != nil {
			homogeneousSource = false
			break
		}
		sourceAddr, ok := netip.AddrFromSlice(ipPath.SourceIp)
		if !ok {
			homogeneousSource = false
			break
		}
		if !firstSourceAddr.IsValid() {
			firstSourceAddr = sourceAddr
		} else if sourceAddr != firstSourceAddr {
			homogeneousSource = false
			break
		}
	}
	send := func(sourceAddr netip.Addr, packets [][]byte, packetOffset int) {
		tun, err := self.activateClient(sourceAddr)
		if err != nil {
			returnErr = errors.Join(returnErr, err)
			return
		}
		if batchTun, ok := tun.(WgBatchTun); ok {
			batchSize := self.uploadPacketBatchSize()
			for packetStart := 0; packetStart < len(packets); packetStart += batchSize {
				packetEnd := min(packetStart+batchSize, len(packets))
				batchPackets := packets[packetStart:packetEnd]
				sentPacketCount := batchTun.SendBorrowedBatch(batchPackets, packetOffset)
				count += sentPacketCount
				if sentPacketCount != len(batchPackets) {
					returnErr = errors.Join(returnErr, DidNotSendError)
				}
			}
			return
		}
		for _, packet := range packets {
			if tun.Send(packet[packetOffset:]) {
				count += 1
			} else {
				returnErr = errors.Join(returnErr, DidNotSendError)
			}
		}
	}
	if homogeneousSource && firstSourceAddr.IsValid() {
		send(firstSourceAddr, bufs, offset)
		return
	}

	type borrowedPacketGroup struct {
		sourceAddr netip.Addr
		packets    [][]byte
	}
	groups := []*borrowedPacketGroup{}
	sourceAddrGroup := map[netip.Addr]*borrowedPacketGroup{}
	for _, buf := range bufs {
		if len(buf) < offset {
			returnErr = errors.Join(returnErr, fmt.Errorf("packet offset %d exceeds buffer size %d", offset, len(buf)))
			continue
		}
		packet := buf[offset:]
		ipPath, err := connect.ParseIpPath(packet)
		if err != nil {
			returnErr = errors.Join(returnErr, err)
			continue
		}
		sourceAddr, ok := netip.AddrFromSlice(ipPath.SourceIp)
		if !ok {
			returnErr = errors.Join(returnErr, fmt.Errorf("unknown source ip"))
			continue
		}
		group := sourceAddrGroup[sourceAddr]
		if group == nil {
			group = &borrowedPacketGroup{
				sourceAddr: sourceAddr,
				packets:    make([][]byte, 0, len(bufs)),
			}
			sourceAddrGroup[sourceAddr] = group
			groups = append(groups, group)
		}
		group.packets = append(group.packets, packet)
	}
	for _, group := range groups {
		send(group.sourceAddr, group.packets, 0)
	}
	return
}

// `uwgtun.Device` implementation
// note that `userwireguard` does not use `connect.MessagPool*`
func (self *WgProxy) Read(bufs [][]byte, sizes []int, offset int) (count int, returnErr error) {
	maximumPacketCount := min(len(bufs), len(sizes), self.downloadPacketBatchSize())
	if maximumPacketCount == 0 {
		return 0, PacketTooLargeError
	}
	for _, buf := range bufs[:maximumPacketCount] {
		if len(buf) < offset {
			return 0, PacketTooLargeError
		}
	}
	copyPacket := func(packet []byte) {
		n := copy(bufs[count][offset:], packet)
		connect.MessagePoolReturn(packet)
		if n < len(packet) {
			returnErr = errors.Join(returnErr, PacketTooLargeError)
		}
		sizes[count] = n
		count += 1
	}

	select {
	case <-self.ctx.Done():
		return 0, fmt.Errorf("done")
	case packet := <-self.receive:
		copyPacket(packet)
	}
	for count < maximumPacketCount {
		select {
		case packet := <-self.receive:
			copyPacket(packet)
		default:
			return
		}
	}
	return
}

// `uwgtun.Device` implementation
func (self *WgProxy) Close() error {
	self.cancel()
	self.device.Close()
	self.closeActiveClients()
	// the senders are stopped (SetReceive(nil) + Cancel in closeActiveClients);
	// drain any packets still queued on the receive channel and return them to
	// the pool, since ownership transferred to us on send.
	for {
		select {
		case packet := <-self.receive:
			connect.MessagePoolReturn(packet)
		default:
			return nil
		}
	}
}

func (self *WgProxy) closeActiveClients() {
	self.closeActiveClientsOnce.Do(func() {
		activeClients := func() map[netip.Addr]WgTun {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			activeClients := self.activeClients
			self.activeClients = map[netip.Addr]WgTun{}
			clear(self.activeClientActivities)
			clear(self.activeTunAddrs)
			return activeClients
		}()
		for addr, activeTun := range activeClients {
			self.syncTunReceive(activeTun, addr)
			activeTun.Cancel()
		}
	})
}

type wgPeerEntry struct {
	addr       netip.Addr
	client     *WgClient
	peerConfig wgtypes.PeerConfig
}

// createPeerEntries converts clients into wg peer configs on a best-effort
// basis. Invalid clients are skipped and their errors are joined into the
// returned error, so callers can apply the valid peers and record exactly the
// clients that were applied. The returned entries and error are independent: a
// non-nil error may accompany a non-empty slice.
func createPeerEntries(clients map[netip.Addr]*WgClient) ([]*wgPeerEntry, error) {
	entries := make([]*wgPeerEntry, 0, len(clients))
	var joinedErr error
	for addr, client := range clients {
		peerConfig, err := createPeerConfig(addr, client)
		if err != nil {
			joinedErr = errors.Join(joinedErr, err)
			continue
		}
		entries = append(entries, &wgPeerEntry{
			addr:       addr,
			client:     client,
			peerConfig: peerConfig,
		})
	}
	return entries, joinedErr
}

func createPeerConfig(addr netip.Addr, client *WgClient) (wgtypes.PeerConfig, error) {
	if client == nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("nil client for %s", addr)
	}
	if client.Tun == nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("nil tun factory for %s", addr)
	}
	if !client.ClientIpv4.Is4() {
		return wgtypes.PeerConfig{}, fmt.Errorf("client %s has invalid ipv4 %s", addr, client.ClientIpv4)
	}
	if addr != client.ClientIpv4 {
		return wgtypes.PeerConfig{}, fmt.Errorf("client map key %s does not match client ipv4 %s", addr, client.ClientIpv4)
	}

	publicKey, err := wgtypes.ParseKey(client.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parse public key for %s: %w", addr, err)
	}
	var presharedKey *wgtypes.Key
	if client.PresharedKey != "" {
		presharedKey_, err := wgtypes.ParseKey(client.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parse preshared key for %s: %w", addr, err)
		}
		presharedKey = &presharedKey_
	}
	return wgtypes.PeerConfig{
		PublicKey:         publicKey,
		PresharedKey:      presharedKey,
		ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{
			{
				IP:   net.IP(client.ClientIpv4.AsSlice()),
				Mask: net.CIDRMask(32, 32),
			},
		},
		// nil leaves the device's endpoint state unchanged (learned from the
		// client's packets); set only by the deploy endpoint handoff
		Endpoint: client.Endpoint,
	}, nil
}

func WgGenKeyPair() (privateKey wgtypes.Key, publicKey wgtypes.Key, err error) {
	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return
	}
	publicKey = privateKey.PublicKey()
	return
}

// WgPublicKeyForPrivateKey derives the wg public key string that corresponds to
// the given private key string. Used to verify that a configured keypair is
// internally consistent (the public key actually belongs to the private key).
func WgPublicKeyForPrivateKey(privateKeyStr string) (string, error) {
	privateKey, err := wgtypes.ParseKey(privateKeyStr)
	if err != nil {
		return "", err
	}
	return privateKey.PublicKey().String(), nil
}

func WgGenKeyPairStrings() (privateKeyStr string, publicKeyStr string, err error) {
	var privateKey wgtypes.Key
	var publicKey wgtypes.Key
	privateKey, publicKey, err = WgGenKeyPair()
	if err != nil {
		return
	}
	privateKeyStr = privateKey.String()
	publicKeyStr = publicKey.String()
	return
}
