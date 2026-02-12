package proxy


import (
	"context"
	"net"
	"strconv"
	"net/netip"
	"sync"
	"fmt"
	"errors"

	"golang.org/x/exp/maps"

	uwgtun "github.com/urnetwork/userwireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
	
)


type WgClient struct {
	PublicKey string
	// TODO this is the signed proxy id
	PresharedKey string
	ClientIpv4 netip.Addr
	Tun *Tun
}


func DefaultWgProxySettings() *WgProxySettings {
	return &WgProxySettings{
		ReceiveSequenceSize: 1024,
		EventsSequenceSize: 16,
	}
}


type WgProxySettings struct {
	PrivateKey string
	ReceiveSequenceSize int
	EventsSequenceSize int
}


// implements wg device:
// - parses packets from wg by source ip to forward to tun
// - all packets from tuns are put back into wg
//   the wg proxy reader is activated on first sent packet from the proxy
type WgProxy struct {
	ctx context.Context
	settings *WgProxySettings

	events chan uwgtun.Event
	receive chan []byte
	

	device *device.Device

	stateLock sync.Mutex

	clients map[netip.Addr]*WgClient
	activeClients map[netip.Addr]*WgClient
}

func NewWgProxyWithDefaults(ctx context.Context) *WgProxy {
	return NewWgProxy(ctx, DefaultWgProxySettings())
}

func NewWgProxy(ctx context.Context, settings *WgProxySettings) *WgProxy {
	wg := &WgProxy{
		ctx: ctx,
		settings: settings,
		events: make(chan uwgtun.Event, settings.EventsSequenceSize),
		receive: make(chan []byte, settings.ReceiveSequenceSize),
		clients: map[netip.Addr]*WgClient{},
		activeClients: map[netip.Addr]*WgClient{},
	}

	logLevel := logger.LogLevelVerbose
	logger := logger.NewLogger(logLevel, "")
	wg.device = device.NewDevice(wg, conn.NewDefaultBind(), logger)

	return wg
}

func (self *WgProxy) ListenAndServe(network string, addr string) error {

	if network != "udp" {
		return fmt.Errorf("network must be udp")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	if host != "" {
		return fmt.Errorf("host bind not supported")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	privateKey, err := wgtypes.ParseKey(self.settings.PrivateKey)
	if err != nil {
		return err
	}

	config := &wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{},
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
func (self *WgProxy) SetClients(clients map[netip.Addr]*WgClient) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	peers := createPeerConfigs(clients)

	config := wgtypes.Config{
		ReplacePeers: true,
		Peers: peers,
	}

	err := self.device.IpcSet(&config)
	if err != nil {
		return err
	}

	self.clients = maps.Clone(clients)
	for addr, activeClient := range self.activeClients {
		if client, ok := self.clients[addr]; ok {
			self.activeClients[addr] = client
			client.Tun.SetReceive(self.receive)
		} else {
			delete(self.activeClients, addr)
			activeClient.Tun.SetReceive(nil)
		}
	}

	return nil
}

// if any devices are already active, keep them active
func (self *WgProxy) AddClients(clients map[netip.Addr]*WgClient) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	peers := createPeerConfigs(clients)

	config := wgtypes.Config{
		ReplacePeers: false,
		Peers: peers,
	}

	err := self.device.IpcSet(&config)
	if err != nil {
		return err
	}

	self.clients = maps.Clone(clients)
	for addr, client := range clients {
		if _, ok := self.activeClients[addr]; ok {
			self.activeClients[addr] = client
			client.Tun.SetReceive(self.receive)
		}
	}

	return nil
}

func (self *WgProxy) activateClient(addr netip.Addr) (*WgClient, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	client, ok := self.activeClients[addr]
	if ok {
		return client, nil
	}

	client, ok = self.clients[addr]
	if ok {
		client.Tun.SetReceive(self.receive)
		self.activeClients[addr] = client
		return client, nil
	}

	return nil, fmt.Errorf("No client found.")
}

func (self *WgProxy) MTU() int {
	return 0
}

func (self *WgProxy) Events() <-chan uwgtun.Event {
	return self.events
}

func (self *WgProxy) AddEvent(event uwgtun.Event) {
	select {
	case <- self.ctx.Done():
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

		ipPath, err := connect.ParseIpPath(packet)
		if err == nil {
			destinationAddr, ok := netip.AddrFromSlice(ipPath.DestinationIp)
			if ok {
				client, err := self.activateClient(destinationAddr)
				if err == nil {
					_, err = client.Tun.Write(packet)
				}
			}
		}

		if err == nil {
			count += 1
		} else {
			returnErr = errors.Join(returnErr, err)
		}
	}
	return
}

func (self *WgProxy) Read(bufs [][]byte, sizes []int, offset int) (count int, returnErr error) {
	select {
	case <- self.ctx.Done():
		return 0, fmt.Errorf("Done.")
	case packet := <- self.receive:
		n := copy(bufs[0][offset:], packet)
		if len(packet) < n {
			returnErr = errors.Join(returnErr, fmt.Errorf("packet too large for buffer"))
		}
		sizes[0] = n
		count += 1
		return
	}
}

func (self *WgProxy) Close() error {
	self.device.Close()
	return nil
}


func createPeerConfigs(clients map[netip.Addr]*WgClient) []wgtypes.PeerConfig {
	var peerConfigs []wgtypes.PeerConfig
	for _, client := range clients {
		publicKey, err := wgtypes.ParseKey(client.PublicKey)
		if err == nil {
			presharedKey, err := wgtypes.ParseKey(client.PresharedKey)
			if err == nil {
				peerConfig := wgtypes.PeerConfig{
					PublicKey:         publicKey,
					PresharedKey: &presharedKey,
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


