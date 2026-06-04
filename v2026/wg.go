package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	// "strconv"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	uwgtun "github.com/urnetwork/userwireguard/v2026/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/urnetwork/glog/v2026"

	"github.com/urnetwork/connect/v2026"
	"github.com/urnetwork/userwireguard/v2026/conn"
	"github.com/urnetwork/userwireguard/v2026/device"
	"github.com/urnetwork/userwireguard/v2026/logger"
)

// FIXME currently the client ipv4 is threaded to the egress providers
//       this can allow tracing a single client ipv4 across multiple providers
//       it should be natted to a standard ipv4

var DidNotSendError = errors.New("did not send")
var PacketTooLargeError = errors.New("packet too large for buffer")

type WgClient struct {
	PublicKey string
	// TODO this is the signed proxy id
	PresharedKey string
	ClientIpv4   netip.Addr
	Tun          func() (WgTun, error)
}

type WgTun interface {
	CancelIfIdle() bool
	Send([]byte) bool
	SetReceive(chan []byte)
	Close() error
}

func DefaultWgProxySettings() *WgProxySettings {
	return &WgProxySettings{
		ReceiveSequenceSize: 1024,
		EventsSequenceSize:  16,
		CheckTunIdleTimeout: 1 * time.Minute,
	}
}

type WgProxySettings struct {
	PrivateKey          string
	ReceiveSequenceSize int
	EventsSequenceSize  int
	CheckTunIdleTimeout time.Duration
	FirewallMark        int
}

// implements wg device:
//   - parses packets from wg by source ip to forward to tun
//   - all packets from tuns are put back into wg
//     the wg proxy reader is activated on first sent packet from the proxy
type WgProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	settings *WgProxySettings

	events  chan uwgtun.Event
	receive chan []byte

	device *device.Device

	stateLock sync.Mutex

	clients       map[netip.Addr]*WgClient
	activeClients map[netip.Addr]WgTun

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

	wg := &WgProxy{
		ctx:           cancelCtx,
		cancel:        cancel,
		settings:      settings,
		events:        make(chan uwgtun.Event, settings.EventsSequenceSize),
		receive:       make(chan []byte, settings.ReceiveSequenceSize),
		clients:       map[netip.Addr]*WgClient{},
		activeClients: map[netip.Addr]WgTun{},
	}

	logger := &logger.Logger{
		Verbosef: func(format string, args ...any) {
			glog.Infof("[wg]"+format, args...)
		},
		Errorf: func(format string, args ...any) {
			glog.Errorf("[wg]"+format, args...)
		},
	}
	wg.device = device.NewDevice(&wgTunDevice{proxy: wg}, conn.NewDefaultBind(), logger)

	go connect.HandleError(wg.run)

	return wg
}

func (self *WgProxy) run() {
	defer self.closeActiveClients()
	defer self.cancel()
	for {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()

			for addr, activeTun := range self.activeClients {
				if activeTun.CancelIfIdle() {
					activeTun.SetReceive(nil)
					delete(self.activeClients, addr)
				}
			}
		}()

		select {
		case <-self.ctx.Done():
			return
		case <-time.After(self.settings.CheckTunIdleTimeout):
		}
	}
}

func (self *WgProxy) ListenAndServe(ipv4 string, ipv6 string, port int) error {
	defer self.cancel()

	privateKey, err := wgtypes.ParseKey(self.settings.PrivateKey)
	if err != nil {
		return err
	}

	glog.Infof("[wg]ipv4=%s ipv6=%s port=%d fwmark=%d\n", ipv4, ipv6, port, self.settings.FirewallMark)
	config := &device.Config{
		Config: wgtypes.Config{
			PrivateKey:   &privateKey,
			ListenPort:   &port,
			ReplacePeers: true,
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
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	// createPeerConfigs is best-effort: invalid clients are skipped and reported
	// here, but the valid peers are still applied.
	peers, err := createPeerConfigs(clients)
	if err != nil {
		glog.Errorf("[wg]SetClients: %s\n", err)
	}

	config := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peers,
	}

	returnErr = self.device.IpcSet(&config)
	if returnErr != nil {
		return
	}

	clear(self.clients)
	for addr, client := range clients {
		self.clients[addr] = client
	}
	for addr, activeTun := range self.activeClients {
		if client, ok := self.clients[addr]; ok {
			tun, err := client.Tun()
			if err == nil {
				if tun != activeTun {
					activeTun.SetReceive(nil)
					activeTun.Close()
					tun.SetReceive(self.receive)
					self.activeClients[addr] = tun
				}
			} else {
				activeTun.SetReceive(nil)
				activeTun.Close()
				delete(self.activeClients, addr)
				returnErr = errors.Join(returnErr, err)
			}
		} else {
			activeTun.SetReceive(nil)
			activeTun.Close()
			delete(self.activeClients, addr)
		}
	}

	return
}

// only clients not already in the state are added
func (self *WgProxy) AddClients(clients map[netip.Addr]*WgClient) (returnErr error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	newClients := maps.Clone(clients)
	for addr, _ := range newClients {
		if _, ok := self.clients[addr]; ok {
			delete(newClients, addr)
		}
	}
	if len(newClients) == 0 {
		return
	}

	// createPeerConfigs is best-effort: invalid clients are skipped and reported
	// here, but the valid peers are still applied.
	peers, err := createPeerConfigs(newClients)
	if err != nil {
		glog.Errorf("[wg]AddClients: %s\n", err)
	}

	config := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}

	returnErr = self.device.IpcSet(&config)
	if returnErr != nil {
		return
	}

	for addr, client := range newClients {
		self.clients[addr] = client
	}

	return
}

func (self *WgProxy) activateClient(addr netip.Addr) (WgTun, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	tun, ok := self.activeClients[addr]
	if ok {
		return tun, nil
	}

	client, ok := self.clients[addr]
	if ok {
		tun, err := client.Tun()
		if err == nil {
			tun.SetReceive(self.receive)
			self.activeClients[addr] = tun
			return tun, nil
		} else {
			return nil, err
		}
	}

	return nil, fmt.Errorf("No client found for %s.", addr)
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
		// defer connect.MessagePoolReturn(packet)
		n := copy(bufs[0][offset:], packet)
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
	return nil
}

func (self *WgProxy) closeActiveClients() {
	self.closeActiveClientsOnce.Do(func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()

		for _, activeTun := range self.activeClients {
			activeTun.SetReceive(nil)
			activeTun.Close()
		}
		clear(self.activeClients)
	})
}

// createPeerConfigs converts clients into wg peer configs on a best-effort
// basis. Invalid clients are skipped and their errors are joined into the
// returned error. The returned configs and error are independent: a non-nil
// error may accompany a non-empty slice. Callers should log the error and
// continue applying the peer configs that were created.
func createPeerConfigs(clients map[netip.Addr]*WgClient) ([]wgtypes.PeerConfig, error) {
	peerConfigs := make([]wgtypes.PeerConfig, 0, len(clients))
	var joinedErr error
	for addr, client := range clients {
		peerConfig, err := createPeerConfig(addr, client)
		if err != nil {
			joinedErr = errors.Join(joinedErr, err)
			continue
		}
		peerConfigs = append(peerConfigs, peerConfig)
	}
	return peerConfigs, joinedErr
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
