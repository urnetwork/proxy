package proxy

import (
	// "bytes"
	"context"
	// "errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	// "regexp"
	mathrand "math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// "github.com/google/gopacket"
	// "github.com/google/gopacket/layers"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	// "gvisor.dev/gvisor/pkg/waiter"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/glog"
)

// const DefaultChannelSize = 64
// const DefaultProxySequenceSize = 64
// const DefaultWriteTimeout = 15 * time.Second

func DefaultTunSettings() *TunSettings {
	return &TunSettings{
		ChannelSize:       64,
		ProxySequenceSize: 64,
		Mtu:               1440,

		DialRace:        4,
		DialRaceTimeout: 2 * time.Second,
		DialTimeout:     15 * time.Second,
	}
}

type TunSettings struct {
	ChannelSize       int
	ProxySequenceSize int
	Mtu               int

	DialRace        int
	DialRaceTimeout time.Duration
	DialTimeout     time.Duration
}

var tunStack = sync.OnceValue(func() *stack.Stack {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true})},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	return stack.New(opts)

})

// FIXME this should be a pool where closed nic ids and addrs can be reused
var nicIdCounter atomic.Uint32
var localIpv4AddressGenerator = sync.OnceValue(func() *connect.AddrGenerator {
	prefix := netip.MustParsePrefix("169.254.0.0/16")
	return connect.NewAddrGenerator(prefix)
})

type Tun struct {
	ctx    context.Context
	cancel context.CancelFunc

	settings *TunSettings

	ep            *channel.Endpoint
	stack         *stack.Stack
	nicId         tcpip.NICID
	receivePacket chan []byte
	// mtu                 int
	// registeredAddresses map[netip.Addr]bool
	dohResolver *connect.DohCache

	stateLock sync.Mutex
}

func CreateTunWithDefaults(ctx context.Context) (*Tun, error) {
	return CreateTun(ctx, DefaultTunSettings())
}

func CreateTun(ctx context.Context, settings *TunSettings) (*Tun, error) {
	return CreateTunWithResolver(ctx, settings, nil)
}

func CreateTunWithResolver(ctx context.Context, settings *TunSettings, dnsResolverSettings *connect.DnsResolverSettings) (*Tun, error) {
	cancelCtx, cancel := context.WithCancel(ctx)

	nicId := tcpip.NICID(nicIdCounter.Add(1))

	localIpv4Address, ok := localIpv4AddressGenerator().Next()
	if !ok {
		return nil, fmt.Errorf("No more local addresses")
	}

	localAddresses := []netip.Addr{
		localIpv4Address,
	}

	ep := channel.New(settings.ChannelSize, uint32(settings.Mtu), tcpip.LinkAddress(fmt.Sprintf("%x", nicId)))

	tun := &Tun{
		ctx:           cancelCtx,
		cancel:        cancel,
		settings:      settings,
		ep:            ep,
		stack:         tunStack(),
		nicId:         nicId,
		receivePacket: make(chan []byte, settings.ProxySequenceSize),
	}

	dohSettings := connect.DefaultDohSettings()
	dohSettings.RequestTimeout = 60 * time.Second
	dohSettings.TlsTimeout = 30 * time.Second
	dohSettings.DialContextSettings = &connect.DialContextSettings{
		DialContext: tun.DialContext,
	}

	if dnsResolverSettings != nil {
		dohSettings.DnsResolverSettings = dnsResolverSettings
	}
	tun.dohResolver = connect.NewDohCache(dohSettings)

	if tcpipErr := tun.stack.CreateNIC(nicId, ep); tcpipErr != nil {
		return nil, fmt.Errorf("Could not create nic err=%s", tcpipErr)
	}

	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}

		if tcpipErr := tun.stack.AddProtocolAddress(nicId, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
			return nil, fmt.Errorf("Could not create add nic address err=%s", tcpipErr)
		}
	}
	tun.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicId})

	ep.AddNotify(tun)

	return tun, nil
}

func (self *Tun) DohCache() *connect.DohCache {
	return self.dohResolver
}

func (self *Tun) Read() ([]byte, error) {
	select {
	case <-self.ctx.Done():
		return nil, fmt.Errorf("Done")
	case m, ok := <-self.receivePacket:
		if !ok {
			return nil, os.ErrClosed
		}
		return m, nil
	}
}

// safe to call from multiple goroutines
func (self *Tun) Write(packet []byte) (int, error) {
	// defer connect.MessagePoolReturn(packet)

	if len(packet) == 0 {
		return 0, nil
	}

	// copy the packet
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})

	switch packet[0] >> 4 {
	case 4:
		self.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		return len(packet), nil
	default:
		return 0, syscall.EAFNOSUPPORT
	}
}

func (self *Tun) WriteNotify() {
	pkt := self.ep.Read()

	// if pkt.IsNil() {
	// 	return
	// }

	// FIXME
	view := pkt.ToView()
	// m := connect.MessagePoolGet(view.Capacity())
	// view.Read(m)
	packet := connect.MessagePoolCopy(view.AsSlice())
	pkt.DecRef()

	select {
	case <-self.ctx.Done():
		connect.MessagePoolReturn(packet)
	case self.receivePacket <- packet:
		// case <-time.After(DefaultWriteTimeout):
		// 	// drop
		// 	connect.MessagePoolReturn(packet)
	}
}

func (self *Tun) convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  self.nicId,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (self *Tun) dialCtx(ctx context.Context) context.Context {
	if ctx == self.ctx {
		return ctx
	}
	dialCtx, dialCancel := context.WithCancel(self.ctx)
	go func() {
		defer dialCancel()
		select {
		case <-ctx.Done():
		case <-self.ctx.Done():
		}
	}()
	return dialCtx
}

func (self *Tun) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	var addrPort netip.AddrPort
	if addr != nil {
		ip, _ := netip.AddrFromSlice(addr.IP)
		addrPort = netip.AddrPortFrom(ip, uint16(addr.Port))
	}
	fa, pn := self.convertToFullAddr(addrPort)
	return gonet.ListenTCP(self.stack, fa, pn)
}

func (self *Tun) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var addrPort netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		addrPort = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	lfa, pn := self.convertToFullAddr(addrPort)
	return gonet.DialUDP(self.stack, &lfa, nil, pn)
}

// safe to call from multiple goroutines
func (self *Tun) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	raceOut := make(chan net.Conn)
	for range self.settings.DialRace {
		go connect.HandleError(func() {
			conn, err := self.dialContext(raceCtx, network, address)
			if err == nil {
				select {
				case <-raceCtx.Done():
				case raceOut <- conn:
				}
			}
		})
		select {
		case conn := <-raceOut:
			return conn, nil
		case <-time.After(self.settings.DialRaceTimeout):
		}
	}
	select {
	case <-raceCtx.Done():
		return nil, fmt.Errorf("Done.")
	case conn := <-raceOut:
		return conn, nil
	case <-time.After(self.settings.DialTimeout - self.settings.DialRaceTimeout):
		return nil, fmt.Errorf("Timeout.")
	}
}

// safe to call from multiple goroutines
func (self *Tun) dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	dialCtx := self.dialCtx(ctx)

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		// address is ip:port
		addrs = append(addrs, addr)
	} else {
		// resolve ips using doh, local

		resolvedAddrs := self.dohResolver.Query(dialCtx, "A", host)
		glog.V(1).Infof("[tun]query doh (%s) found %v\n", host, resolvedAddrs)
		for _, addr := range resolvedAddrs {
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("Could not resolve %s", address)
	}

	addr := addrs[mathrand.Intn(len(addrs))]

	// var returnErr error
	// for _, addr := range addrs {
	addrPort := netip.AddrPortFrom(addr, uint16(port))

	switch network {
	case "tcp", "tcp4", "tcp6":
		fa, pn := self.convertToFullAddr(addrPort)
		conn, err := gonet.DialTCP(self.stack, fa, pn)
		if err == nil {
			glog.V(1).Infof("[tun]tcp connect (%s)->%s success\n", host, addrPort)
			return conn, nil
		}
		glog.V(1).Infof("[tun]tcp connect (%s)->%s err = %s\n", host, addrPort, err)
		return nil, err
	case "udp", "udp4", "udp6":
		fa, pn := self.convertToFullAddr(addrPort)
		conn, err := gonet.DialUDP(self.stack, nil, &fa, pn)
		if err == nil {
			glog.V(1).Infof("[tun]udp connect (%s)->%s success\n", host, addrPort)
			return conn, nil
		}
		glog.V(1).Infof("[tun]tcp connect (%s)->%s err = %s\n", host, addrPort, err)
		return nil, err
	default:
		return nil, fmt.Errorf("Unsupported network %s", network)
	}
	// }

	// return nil, returnErr
}

func (self *Tun) Dial(network, address string) (net.Conn, error) {
	return self.DialContext(context.Background(), network, address)
}

func (self *Tun) Close() error {
	self.cancel()
	self.stack.RemoveNIC(self.nicId)
	self.ep.Close()
	return nil
}
