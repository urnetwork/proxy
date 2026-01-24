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
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	mathrand "math/rand"

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

	
	"github.com/urnetwork/glog/v2026"
	"github.com/urnetwork/connect/v2026"
)


const DefaultChannelSize = 64
const DefaultProxySequenceSize = 64
// const DefaultWriteTimeout = 15 * time.Second


var tunStack = sync.OnceValue(func()(*stack.Stack) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic:true})},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	return stack.New(opts)

})


type Net struct {
	ctx context.Context
	cancel context.CancelFunc
	ep                  *channel.Endpoint
	stack               *stack.Stack
	nicId tcpip.NICID
	incomingPacket      chan []byte
	mtu                 int
	mu                  sync.Mutex
	// registeredAddresses map[netip.Addr]bool
	dohResolver         *connect.DohCache
	
}


func (tnet *Net) DohCache() *connect.DohCache {
	return tnet.dohResolver
}

// type Net netTun
type Device interface {
	Read() ([]byte, error)

	// Write one or more packets to the device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write([]byte) (int, error)

	// Close stops the Device and closes the Event channel.
	Close() error
}

// FIXME this should be a pool where closed nic ids and addrs can be reused
var nicIdCounter atomic.Uint32
var localIpv4AddressGenerator = sync.OnceValue(func()(*connect.AddrGenerator) {
	prefix := netip.MustParsePrefix("169.254.0.0/16")
	return connect.NewAddrGenerator(prefix)
})


func CreateNetTUN(ctx context.Context, mtu int) (*Net, error) {
	cancelCtx, cancel := context.WithCancel(ctx)

	nicId := tcpip.NICID(nicIdCounter.Add(1))

	localIpv4Address, ok := localIpv4AddressGenerator().Next()
	if !ok {
		return nil, fmt.Errorf("No more local addresses")
	}

	localAddresses := []netip.Addr{
		localIpv4Address,
	}
	
	dev := &Net{
		ctx: cancelCtx,
		cancel: cancel,
		ep:                  channel.New(DefaultChannelSize, uint32(mtu), tcpip.LinkAddress(fmt.Sprintf("%x", nicId))),
		stack:               tunStack(),
		nicId: nicId,
		incomingPacket:      make(chan []byte, DefaultProxySequenceSize),
		mtu:                 mtu,
	}

	dohSettings := connect.DefaultDohSettings()
	dohSettings.RequestTimeout = 60 * time.Second
	dohSettings.TlsTimeout = 30 * time.Second
	dohSettings.DialContextSettings = &connect.DialContextSettings{
		DialContext: dev.DialContext,
	}
	dev.dohResolver = connect.NewDohCache(dohSettings)

	


	
	if tcpipErr := dev.stack.CreateNIC(nicId, dev.ep); tcpipErr != nil {
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
		
		if tcpipErr := dev.stack.AddProtocolAddress(nicId, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
			return nil, fmt.Errorf("Could not create add nic address err=%s", tcpipErr)
		}
	}
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicId})

	dev.ep.AddNotify(dev)

	return dev, nil
}

// func (tun *Net) Name() (string, error) {
// 	return "go", nil
// }

// func (tun *Net) File() *os.File {
// 	return nil
// }

func (tun *Net) Read() ([]byte, error) {
	select {
	case <- tun.ctx.Done():
		return nil, fmt.Errorf("Done")
	case m, ok := <-tun.incomingPacket:
		if !ok {
			return nil, os.ErrClosed
		}
		return m, nil
	}
}

// safe to call from multiple goroutines
func (tun *Net) Write(packet []byte) (int, error) {
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
		tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		return len(packet), nil
	default:
		return 0, syscall.EAFNOSUPPORT
	}
}

func (tun *Net) WriteNotify() {
	pkt := tun.ep.Read()

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
	case <- tun.ctx.Done():
		connect.MessagePoolReturn(packet)
	case tun.incomingPacket <- packet:
	// case <-time.After(DefaultWriteTimeout):
	// 	// drop
	// 	connect.MessagePoolReturn(packet)
	}
}

func (tun *Net) Close() error {
	tun.cancel()

	tun.stack.RemoveNIC(tun.nicId)

	tun.ep.Close()

	// tun.stack.Close()

	// if tun.incomingPacket != nil {
	// 	close(tun.incomingPacket)
	// }

	return nil
}

// func (tun *Net) Mtu() (int, error) {
// 	return tun.mtu, nil
// }

// func (tun *Net) BatchSize() int {
// 	return 1
// }

func (tun *Net) convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  tun.nicId,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (net *Net) dialCtx(ctx context.Context) context.Context {
	if ctx == net.ctx {
		return ctx
	}
	dialCtx, dialCancel := context.WithCancel(net.ctx)
	go func() {
		defer dialCancel()
		select {
		case <- ctx.Done():
		case <- net.ctx.Done():
		}
	}()
	return dialCtx
}

// func (net *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
// 	fa, pn := net.convertToFullAddr(addr)
// 	return gonet.DialContextTCP(net.dialCtx(ctx), net.stack, fa, pn)
// }

// func (net *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
// 	var addrPort netip.AddrPort
// 	if addr != nil {
// 		ip, _ := netip.AddrFromSlice(addr.IP)
// 		addrPort = netip.AddrPortFrom(ip, uint16(addr.Port))
// 	}
// 	return net.DialContextTCPAddrPort(net.dialCtx(ctx), addrPort)
// }

// func (net *Net) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
// 	fa, pn := net.convertToFullAddr(addr)
// 	return gonet.DialTCP(net.stack, fa, pn)
// }

// func (net *Net) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
// 	if addr == nil {
// 		return net.DialTCPAddrPort(netip.AddrPort{})
// 	}
// 	ip, _ := netip.AddrFromSlice(addr.IP)
// 	return net.DialTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
// }

// func (net *Net) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
// 	fa, pn := net.convertToFullAddr(addr)
// 	return gonet.ListenTCP(net.stack, fa, pn)
// }

func (net *Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	var addrPort netip.AddrPort
	if addr != nil {
		ip, _ := netip.AddrFromSlice(addr.IP)
		addrPort = netip.AddrPortFrom(ip, uint16(addr.Port))
	}
	fa, pn := net.convertToFullAddr(addrPort)
	return gonet.ListenTCP(net.stack, fa, pn)
}

// func (net *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
// 	var lfa, rfa *tcpip.FullAddress
// 	var pn tcpip.NetworkProtocolNumber
// 	if laddr.IsValid() || laddr.Port() > 0 {
// 		var addr tcpip.FullAddress
// 		addr, pn = net.convertToFullAddr(laddr)
// 		lfa = &addr
// 	}
// 	if raddr.IsValid() || raddr.Port() > 0 {
// 		var addr tcpip.FullAddress
// 		addr, pn = net.convertToFullAddr(raddr)
// 		rfa = &addr
// 	}
// 	return gonet.DialUDP(net.stack, lfa, rfa, pn)
// }

// func (net *Net) DialContextUDPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.UDPConn, error) {
// 	return net.DialUDPAddrPort(netip.AddrPort{}, addr)
// }

// func (net *Net) DialContextUDP(ctx context.Context, addr *net.UDPAddr) (*gonet.UDPConn, error) {
// 	if addr == nil {
// 		return net.DialContextUDPAddrPort(ctx, netip.AddrPort{})
// 	}
// 	ip, _ := netip.AddrFromSlice(addr.IP)
// 	return net.DialContextUDPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(addr.Port)))
// }

// func (net *Net) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
// 	return net.DialUDPAddrPort(laddr, netip.AddrPort{})
// }

// func (net *Net) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
// 	var la, ra netip.AddrPort
// 	if laddr != nil {
// 		ip, _ := netip.AddrFromSlice(laddr.IP)
// 		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
// 	}
// 	if raddr != nil {
// 		ip, _ := netip.AddrFromSlice(raddr.IP)
// 		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
// 	}
// 	return net.DialUDPAddrPort(la, ra)
// }

func (net *Net) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var addrPort netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		addrPort = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	lfa, pn := net.convertToFullAddr(addrPort)
	return gonet.DialUDP(net.stack, &lfa, nil, pn)
}

// type PingConn struct {
// 	net  *Net
// 	laddr    PingAddr
// 	raddr    PingAddr
// 	wq       waiter.Queue
// 	ep       tcpip.Endpoint
// 	deadline *time.Timer
// }

// type PingAddr struct{ addr netip.Addr }

// func (ia PingAddr) String() string {
// 	return ia.addr.String()
// }

// func (ia PingAddr) Network() string {
// 	if ia.addr.Is4() {
// 		return "ping4"
// 	} else if ia.addr.Is6() {
// 		return "ping6"
// 	}
// 	return "ping"
// }

// func (ia PingAddr) Addr() netip.Addr {
// 	return ia.addr
// }

// func PingAddrFromAddr(addr netip.Addr) *PingAddr {
// 	return &PingAddr{addr}
// }

// func (net *Net) DialPingAddr(laddr, raddr netip.Addr) (*PingConn, error) {
// 	if !laddr.IsValid() && !raddr.IsValid() {
// 		return nil, errors.New("ping dial: invalid address")
// 	}
// 	v6 := laddr.Is6() || raddr.Is6()
// 	bind := laddr.IsValid()
// 	if !bind {
// 		if v6 {
// 			laddr = netip.IPv6Unspecified()
// 		} else {
// 			laddr = netip.IPv4Unspecified()
// 		}
// 	}

// 	tn := icmp.ProtocolNumber4
// 	pn := ipv4.ProtocolNumber
// 	if v6 {
// 		tn = icmp.ProtocolNumber6
// 		pn = ipv6.ProtocolNumber
// 	}

// 	pc := &PingConn{
// 		net: net,
// 		laddr:    PingAddr{laddr},
// 		deadline: time.NewTimer(time.Hour << 10),
// 	}
// 	pc.deadline.Stop()

// 	ep, tcpipErr := net.stack.NewEndpoint(tn, pn, &pc.wq)
// 	if tcpipErr != nil {
// 		return nil, fmt.Errorf("ping socket: endpoint: %s", tcpipErr)
// 	}
// 	pc.ep = ep

// 	if bind {
// 		fa, _ := net.convertToFullAddr(netip.AddrPortFrom(laddr, 0))
// 		if tcpipErr = pc.ep.Bind(fa); tcpipErr != nil {
// 			return nil, fmt.Errorf("ping bind: %s", tcpipErr)
// 		}
// 	}

// 	if raddr.IsValid() {
// 		pc.raddr = PingAddr{raddr}
// 		fa, _ := net.convertToFullAddr(netip.AddrPortFrom(raddr, 0))
// 		if tcpipErr = pc.ep.Connect(fa); tcpipErr != nil {
// 			return nil, fmt.Errorf("ping connect: %s", tcpipErr)
// 		}
// 	}

// 	return pc, nil
// }

// func (net *Net) ListenPingAddr(laddr netip.Addr) (*PingConn, error) {
// 	return net.DialPingAddr(laddr, netip.Addr{})
// }

// func (net *Net) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
// 	var la, ra netip.Addr
// 	if laddr != nil {
// 		la = laddr.addr
// 	}
// 	if raddr != nil {
// 		ra = raddr.addr
// 	}
// 	return net.DialPingAddr(la, ra)
// }

// func (net *Net) ListenPing(laddr *PingAddr) (*PingConn, error) {
// 	var la netip.Addr
// 	if laddr != nil {
// 		la = laddr.addr
// 	}
// 	return net.ListenPingAddr(la)
// }

// func (pc *PingConn) LocalAddr() net.Addr {
// 	return pc.laddr
// }

// func (pc *PingConn) RemoteAddr() net.Addr {
// 	return pc.raddr
// }

// func (pc *PingConn) Close() error {
// 	pc.deadline.Reset(0)
// 	pc.ep.Close()
// 	return nil
// }

// func (pc *PingConn) SetWriteDeadline(t time.Time) error {
// 	return errors.New("not implemented")
// }

// func (pc *PingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
// 	var na netip.Addr
// 	switch v := addr.(type) {
// 	case *PingAddr:
// 		na = v.addr
// 	case *net.IPAddr:
// 		na, _ = netip.AddrFromSlice(v.IP)
// 	default:
// 		return 0, fmt.Errorf("ping write: wrong net.Addr type")
// 	}
// 	if !((na.Is4() && pc.laddr.addr.Is4()) || (na.Is6() && pc.laddr.addr.Is6())) {
// 		return 0, fmt.Errorf("ping write: mismatched protocols")
// 	}

// 	buf := bytes.NewReader(p)
// 	rfa, _ := pc.net.convertToFullAddr(netip.AddrPortFrom(na, 0))
// 	// won't block, no deadlines
// 	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
// 		To: &rfa,
// 	})
// 	if tcpipErr != nil {
// 		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
// 	}

// 	return int(n64), nil
// }

// func (pc *PingConn) Write(p []byte) (n int, err error) {
// 	return pc.WriteTo(p, &pc.raddr)
// }

// func (pc *PingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
// 	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
// 	pc.wq.EventRegister(&e)
// 	defer pc.wq.EventUnregister(&e)

// 	select {
// 	case <-pc.net.ctx.Done():
// 		return 0, nil, fmt.Errorf("Done")
// 	case <-pc.deadline.C:
// 		return 0, nil, os.ErrDeadlineExceeded
// 	case <-notifyCh:
// 		// FIXME ctx
// 	}

// 	w := tcpip.SliceWriter(p)

// 	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
// 		NeedRemoteAddr: true,
// 	})
// 	if tcpipErr != nil {
// 		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
// 	}

// 	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
// 	return res.Count, &PingAddr{remoteAddr}, nil
// }

// func (pc *PingConn) Read(p []byte) (n int, err error) {
// 	n, _, err = pc.ReadFrom(p)
// 	return
// }

// func (pc *PingConn) SetDeadline(t time.Time) error {
// 	// pc.SetWriteDeadline is unimplemented

// 	return pc.SetReadDeadline(t)
// }

// func (pc *PingConn) SetReadDeadline(t time.Time) error {
// 	pc.deadline.Reset(time.Until(t))
// 	return nil
// }

// safe to call from multiple goroutines
func (tnet *Net) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {

	dialCtx := tnet.dialCtx(ctx)

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

		resolvedAddrs := tnet.dohResolver.Query(dialCtx, "A", host)
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
			fa, pn := tnet.convertToFullAddr(addrPort)
			conn, err := gonet.DialTCP(tnet.stack, fa, pn)
			if err == nil {
				glog.V(1).Infof("[tun]tcp connect (%s)->%s success\n", host, addrPort)
				return conn, nil
			}
			glog.V(1).Infof("[tun]tcp connect (%s)->%s err = %s\n", host, addrPort, err)
			return nil, err
		case "udp", "udp4", "udp6":
			fa, pn := tnet.convertToFullAddr(addrPort)
			conn, err := gonet.DialUDP(tnet.stack, nil, &fa, pn)
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

func (tnet *Net) Dial(network, address string) (net.Conn, error) {
	return tnet.DialContext(context.Background(), network, address)
}

