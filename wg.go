package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	uwgtun "github.com/urnetwork/userwireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/urnetwork/glog"

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
	wg.device = device.NewDevice(wg, conn.NewDefaultBind(), logger)

	go connect.HandleError(wg.run)

	return wg
}

func (self *WgProxy) run() {
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

func (self *WgProxy) ListenAndServe(network string, addr string) error {
	if network != "udp" {
		return fmt.Errorf("network must be udp")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	if host != "" {
		glog.Warningf("[wg]binding is not supported (%s:%d). WireGuard will listen on *:%d.\n", host, port, port)
	}

	privateKey, err := wgtypes.ParseKey(self.settings.PrivateKey)
	if err != nil {
		return err
	}

	config := &wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{},
	}

	err = self.device.IpcSet(config)
	if err != nil {
		return err
	}

	self.device.AddEvent(uwgtun.EventUp)

	select {
	case <-self.device.Wait():
	}
	return nil
}

// hot patches the devices into the wg server
// if the device is already active, keep it active
func (self *WgProxy) SetClients(clients map[netip.Addr]*WgClient) (returnErr error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	peers := createPeerConfigs(clients)

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
				tun.SetReceive(self.receive)
				self.activeClients[addr] = tun
			} else {
				activeTun.SetReceive(nil)
				delete(self.activeClients, addr)
				returnErr = errors.Join(returnErr, err)
			}
		} else {
			activeTun.SetReceive(nil)
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

	peers := createPeerConfigs(newClients)

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
func (self *WgProxy) Read(bufs [][]byte, sizes []int, offset int) (count int, returnErr error) {
	select {
	case <-self.ctx.Done():
		return 0, fmt.Errorf("Done.")
	case packet := <-self.receive:
		defer connect.MessagePoolReturn(packet)
		n := copy(bufs[0][offset:], packet)
		if len(packet) < n {
			returnErr = errors.Join(returnErr, PacketTooLargeError)
		}
		sizes[0] = n
		count += 1
		return
	}
}

// `uwgtun.Device` implementation
func (self *WgProxy) Close() error {
	self.device.Close()
	return nil
}

func createPeerConfigs(clients map[netip.Addr]*WgClient) []wgtypes.PeerConfig {
	var peerConfigs []wgtypes.PeerConfig
	for _, client := range clients {
		publicKey, err := wgtypes.ParseKey(client.PublicKey)
		if err == nil {
			var presharedKey *wgtypes.Key
			if client.PresharedKey != "" {
				var presharedKey_ wgtypes.Key
				presharedKey_, err = wgtypes.ParseKey(client.PresharedKey)
				if err == nil {
					presharedKey = &presharedKey_
				}
			}
			if err == nil {
				peerConfig := wgtypes.PeerConfig{
					PublicKey:         publicKey,
					PresharedKey:      presharedKey,
					ReplaceAllowedIPs: true,
					AllowedIPs: []net.IPNet{
						{
							IP:   net.IP(client.ClientIpv4.AsSlice()),
							Mask: net.CIDRMask(32, 32),
						},
					},
				}
				peerConfigs = append(peerConfigs, peerConfig)
			}
		}
	}
	return peerConfigs
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
