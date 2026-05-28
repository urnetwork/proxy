package proxy

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/urnetwork/userwireguard/conn"
	uwgdevice "github.com/urnetwork/userwireguard/device"
	"github.com/urnetwork/userwireguard/logger"
	"github.com/urnetwork/userwireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWgProxyWithUserspaceWireGuardClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverPrivate, serverPublic, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}
	clientPrivate, clientPublic, err := WgGenKeyPair()
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}

	settings := DefaultWgProxySettings()
	settings.PrivateKey = serverPrivate
	settings.CheckTunIdleTimeout = 10 * time.Second
	wg := NewWgProxy(ctx, settings)
	t.Cleanup(func() {
		_ = wg.Close()
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- wg.ListenAndServe("127.0.0.1", "::1", 0)
	}()
	serverPort := waitForWgListenPort(t, wg, errCh)

	clientIP := netip.MustParseAddr("10.0.0.2")
	serverIP := netip.MustParseAddr("10.0.0.1")
	proxyTun := newRecordingWgTun()
	if err := wg.SetClients(map[netip.Addr]*WgClient{
		clientIP: {
			PublicKey:  clientPublic.String(),
			ClientIpv4: clientIP,
			Tun: func() (WgTun, error) {
				return proxyTun, nil
			},
		},
	}); err != nil {
		t.Fatalf("set clients: %v", err)
	}

	clientTun := tuntest.NewChannelTUN()
	clientDevice := uwgdevice.NewDevice(
		clientTun.TUN(),
		conn.NewDefaultBind(),
		logger.NewLogger(logger.LogLevelError, "client: "),
	)
	t.Cleanup(clientDevice.Close)

	serverPublicKey, err := wgtypes.ParseKey(serverPublic)
	if err != nil {
		t.Fatalf("parse server public key: %v", err)
	}
	zeroPort := 0
	clientConfig := wgtypes.Config{
		PrivateKey:   &clientPrivate,
		ListenPort:   &zeroPort,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPublicKey,
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: serverPort,
				},
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					{
						IP:   net.IP(serverIP.AsSlice()),
						Mask: net.CIDRMask(32, 32),
					},
				},
			},
		},
	}
	if err := clientDevice.IpcSet(&clientConfig); err != nil {
		t.Fatalf("configure client device: %v", err)
	}
	if err := clientDevice.Up(); err != nil {
		t.Fatalf("bring client device up: %v", err)
	}

	clientToProxyPacket := udpIPv4Packet(clientIP, serverIP, []byte("client-to-proxy"))
	clientTun.Outbound <- clientToProxyPacket
	gotFromClient := proxyTun.waitSent(t)
	if !bytes.Equal(gotFromClient, clientToProxyPacket) {
		t.Fatalf("proxy tun got different packet from client")
	}

	proxyToClientPacket := udpIPv4Packet(serverIP, clientIP, []byte("proxy-to-client"))
	receive := proxyTun.waitReceive(t)
	select {
	case receive <- proxyToClientPacket:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out sending proxy packet to wg device")
	}

	select {
	case got := <-clientTun.Inbound:
		if !bytes.Equal(got, proxyToClientPacket) {
			t.Fatalf("client tun got different packet from proxy")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not receive packet from proxy")
	}

	_ = wg.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("wg listen returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wg proxy did not stop")
	}
}

func TestWgProxyRejectsMismatchedClientMapKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := NewWgProxy(ctx, DefaultWgProxySettings())
	defer wg.Close()

	_, publicKey, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	mapKey := netip.MustParseAddr("10.0.0.2")
	clientIP := netip.MustParseAddr("10.0.0.3")
	err = wg.SetClients(map[netip.Addr]*WgClient{
		mapKey: {
			PublicKey:  publicKey,
			ClientIpv4: clientIP,
			Tun: func() (WgTun, error) {
				return newRecordingWgTun(), nil
			},
		},
	})
	if err == nil {
		t.Fatal("SetClients succeeded with mismatched map key and client ipv4")
	}
}

func waitForWgListenPort(t *testing.T, wg *WgProxy, errCh <-chan error) int {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("wg listen returned before ready: %v", err)
		default:
		}

		dev, err := wg.device.IpcGet()
		if err == nil && dev.ListenPort != 0 {
			return dev.ListenPort
		}
		if time.Now().After(deadline) {
			t.Fatalf("wg listen port did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type recordingWgTun struct {
	sent         chan []byte
	receiveReady chan chan []byte

	stateLock sync.Mutex
	receive   chan []byte
}

func newRecordingWgTun() *recordingWgTun {
	return &recordingWgTun{
		sent:         make(chan []byte, 4),
		receiveReady: make(chan chan []byte, 1),
	}
}

func (self *recordingWgTun) CancelIfIdle() bool {
	return false
}

func (self *recordingWgTun) Send(packet []byte) bool {
	packetCopy := append([]byte(nil), packet...)
	select {
	case self.sent <- packetCopy:
		return true
	default:
		return false
	}
}

func (self *recordingWgTun) SetReceive(receive chan []byte) {
	self.stateLock.Lock()
	self.receive = receive
	self.stateLock.Unlock()
	if receive != nil {
		select {
		case self.receiveReady <- receive:
		default:
		}
	}
}

func (self *recordingWgTun) Close() error {
	return nil
}

func (self *recordingWgTun) waitSent(t *testing.T) []byte {
	t.Helper()

	select {
	case packet := <-self.sent:
		return packet
	case <-time.After(5 * time.Second):
		t.Fatal("proxy tun did not receive client packet")
		return nil
	}
}

func (self *recordingWgTun) waitReceive(t *testing.T) chan []byte {
	t.Helper()

	self.stateLock.Lock()
	receive := self.receive
	self.stateLock.Unlock()
	if receive != nil {
		return receive
	}

	select {
	case receive := <-self.receiveReady:
		return receive
	case <-time.After(5 * time.Second):
		t.Fatal("proxy tun receive channel was not attached")
		return nil
	}
}

func udpIPv4Packet(src netip.Addr, dst netip.Addr, payload []byte) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP(src.AsSlice()),
		DstIP:    net.IP(dst.AsSlice()),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(443),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}
