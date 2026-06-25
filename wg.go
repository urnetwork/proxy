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
	"time"

	uwgtun "github.com/urnetwork/userwireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
)

// FIXME currently the client ipv4 is threaded to the egress providers
//       this can allow tracing a single client ipv4 across multiple providers
//       it should be natted to a standard ipv4

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
}

type WgTun interface {
	// CancelIfIdle() bool
	Active() bool
	UpdateActivity() bool
	Send([]byte) bool
	SetReceive(chan []byte)
	Cancel()
}

func DefaultWgProxySettings() *WgProxySettings {
	return &WgProxySettings{
		ReceiveSequenceSize: 1024,
		EventsSequenceSize:  16,
		CheckTunIdleTimeout: 1 * time.Minute,
		ClientBatchSize:     256,
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

	closeActiveClientsOnce sync.Once
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

func (self *wgTunDevice) Close() error {
	self.proxy.cancel()
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
	}()

	_, returnErr = self.addClients(clients)

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
			actives = append(actives, activeEntry{addr, activeTun, self.clients[addr]})
		}
	}()
	for _, a := range actives {
		if a.client == nil {
			a.activeTun.SetReceive(nil)
			a.activeTun.Cancel()
			self.removeActiveClient(a.addr, a.activeTun)
			continue
		}
		tun, err := a.client.Tun()
		if err != nil {
			a.activeTun.SetReceive(nil)
			a.activeTun.Cancel()
			self.removeActiveClient(a.addr, a.activeTun)
			returnErr = errors.Join(returnErr, err)
			continue
		}
		if tun != a.activeTun {
			a.activeTun.SetReceive(nil)
			a.activeTun.Cancel()
			tun.SetReceive(self.receive)
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.activeClients[a.addr] = tun
			}()
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
		delete(self.activeClients, addr)
	}
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
	return self.addClients(clients)
}

// addClients programs the given clients' peers into the device and records them.
// The caller must hold controlLock (serializing control-plane device writes).
// device.IpcSet runs WITHOUT stateLock; stateLock is taken only to record each
// batch right after it is programmed, minimizing the window where a peer exists
// in the device but is not yet routable via activateClient.
func (self *WgProxy) addClients(clients map[netip.Addr]*WgClient) (applied map[netip.Addr]*WgClient, returnErr error) {
	applied = map[netip.Addr]*WgClient{}
	if len(clients) == 0 {
		return
	}

	// createPeerEntries is best-effort: invalid clients are skipped and joined
	// into the error, but the valid peers are still applied.
	entries, returnErr := createPeerEntries(clients)

	batchSize := self.settings.ClientBatchSize
	if batchSize <= 0 {
		batchSize = len(entries)
	}

	record := func(batch []*wgPeerEntry) {
		now := time.Now()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range batch {
			self.clients[entry.addr] = entry.client
			self.clientAddTimes[entry.addr] = now
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

// RemoveClients removes the peers for the given addresses from the device and
// forgets the clients. Only clients whose config was last applied before
// `addedBefore` are removed: a reconcile pass computes removals from a db
// snapshot, and the cutoff makes a client applied concurrently with the
// snapshot (e.g. by a warmup call) immune until the next pass.
func (self *WgProxy) RemoveClients(addedBefore time.Time, addrs ...netip.Addr) (returnErr error) {
	self.controlLock.Lock()
	defer self.controlLock.Unlock()

	for _, addr := range addrs {
		// decide removal eligibility under the lock, then release it before the
		// device write
		var client *WgClient
		func() {
			self.stateLock.RLock()
			defer self.stateLock.RUnlock()
			c, ok := self.clients[addr]
			if !ok {
				return
			}
			if addTime, ok := self.clientAddTimes[addr]; ok && !addTime.Before(addedBefore) {
				// applied at or after the cutoff: keep (grace window)
				return
			}
			client = c
		}()
		if client == nil {
			continue
		}

		publicKey, err := wgtypes.ParseKey(client.PublicKey)
		if err != nil {
			// the key parsed when the client was applied, so this is unexpected
			returnErr = errors.Join(returnErr, fmt.Errorf("remove client %s: %w", addr, err))
			continue
		}
		config := wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:  publicKey,
					Remove:     true,
					UpdateOnly: true,
				},
			},
		}
		// program the device outside stateLock (the device is internally
		// synchronized) so the data path is not blocked while peers are removed
		if err := self.device.IpcSet(&config); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove client %s: %w", addr, err))
			continue
		}

		// forget the client and capture any active tun to tear down after the lock
		var activeTun WgTun
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.clients, addr)
			delete(self.clientAddTimes, addr)
			if t, ok := self.activeClients[addr]; ok {
				activeTun = t
				delete(self.activeClients, addr)
			}
		}()
		if activeTun != nil {
			activeTun.SetReceive(nil)
			activeTun.Cancel()
		}
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
	self.stateLock.RUnlock()
	if tun != nil && tun.Active() && tun.UpdateActivity() {
		// Re-assert wg "receive" mode on each call. The proxy device is shared per
		// proxy id, so a tun-based call (http/socks) may have reset it to tun mode
		// via SetReceive(nil). The device's SetReceive is idempotent when the
		// channel is unchanged, so this is free in the common case.
		tun.SetReceive(self.receive)
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
	tun.SetReceive(self.receive)

	self.stateLock.Lock()
	// the client may have been removed while the device was being created
	// (RemoveClients deletes clients[addr] under this lock); if so, do not
	// publish a tun for it
	if _, stillClient := self.clients[addr]; !stillClient {
		self.stateLock.Unlock()
		tun.SetReceive(nil)
		tun.Cancel()
		return nil, fmt.Errorf("No client found for %s.", addr)
	}
	self.activeClients[addr] = tun
	self.stateLock.Unlock()
	return tun, nil
}

func (self *WgProxy) MTU() int {
	return 0
}

func (self *WgProxy) Events() <-chan uwgtun.Event {
	return self.events
}

func (self *WgProxy) AddEvent(event uwgtun.Event) {
	select {
	case <-self.ctx.Done():
	case self.events <- event:
	}
}

func (self *WgProxy) BatchSize() int {
	return 1
}

// `uwgtun.Device` implementation
func (self *WgProxy) Write(bufs [][]byte, offset int) (count int, returnErr error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		// packet := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)

		err := func() error {
			ipPath, err := connect.ParseIpPath(packet)
			if err != nil {
				return err
			}
			sourceAddr, ok := netip.AddrFromSlice(ipPath.SourceIp)
			if !ok {
				return fmt.Errorf("Unknown source ip")
			}
			tun, err := self.activateClient(sourceAddr)
			if err != nil {
				return err
			}
			success := tun.Send(packet)
			if !success {
				return DidNotSendError
			}
			return nil
		}()

		if err == nil {
			count += 1
		} else {
			returnErr = errors.Join(returnErr, err)
		}
	}
	return
}

// `uwgtun.Device` implementation
// note that `userwireguard` does not use `connect.MessagPool*`
func (self *WgProxy) Read(bufs [][]byte, sizes []int, offset int) (count int, returnErr error) {
	select {
	case <-self.ctx.Done():
		return 0, fmt.Errorf("Done.")
	case packet := <-self.receive:
		// ownership transferred to us on the successful send; copy into the
		// device buffer and return the shared packet to the pool.
		n := copy(bufs[0][offset:], packet)
		connect.MessagePoolReturn(packet)
		if n < len(packet) {
			returnErr = errors.Join(returnErr, PacketTooLargeError)
		}
		sizes[0] = n
		count += 1
		return
	}
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
		self.stateLock.Lock()
		defer self.stateLock.Unlock()

		for _, activeTun := range self.activeClients {
			activeTun.SetReceive(nil)
			activeTun.Cancel()
		}
		clear(self.activeClients)
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
