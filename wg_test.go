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

func TestCreatePeerEntriesSkipsInvalidClients(t *testing.T) {
	_, publicKey, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }

	validIP := netip.MustParseAddr("10.0.0.3")
	entries, err := createPeerEntries(map[netip.Addr]*WgClient{
		// valid: map key matches ClientIpv4 and the public key parses
		validIP: {
			PublicKey:  publicKey,
			ClientIpv4: validIP,
			Tun:        tun,
		},
		// invalid: map key does not match ClientIpv4
		netip.MustParseAddr("10.0.0.2"): {
			PublicKey:  publicKey,
			ClientIpv4: netip.MustParseAddr("10.0.0.4"),
			Tun:        tun,
		},
		// invalid: public key does not parse
		netip.MustParseAddr("10.0.0.5"): {
			PublicKey:  "not-a-valid-key",
			ClientIpv4: netip.MustParseAddr("10.0.0.5"),
			Tun:        tun,
		},
	})

	// Partial success: the invalid clients are reported, but the valid peer is
	// still returned.
	if err == nil {
		t.Fatal("createPeerEntries did not report the invalid clients")
	}
	if len(entries) != 1 {
		t.Fatalf("createPeerEntries returned %d entries, want 1 (only the valid client)", len(entries))
	}
	if entries[0].addr != validIP {
		t.Fatalf("createPeerEntries entry addr = %v, want the valid client", entries[0].addr)
	}
	wantKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if entries[0].peerConfig.PublicKey != wantKey {
		t.Fatalf("peer public key = %v, want the valid client key", entries[0].peerConfig.PublicKey)
	}
}

func TestWgProxySetClientsContinuesPastInvalidClients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := NewWgProxy(ctx, DefaultWgProxySettings())
	defer wg.Close()

	_, validKey, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate valid keypair: %v", err)
	}
	_, invalidKey, err := WgGenKeyPairStrings()
	if err != nil {
		t.Fatalf("generate invalid keypair: %v", err)
	}
	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }

	validIP := netip.MustParseAddr("10.0.0.3")
	// One valid client alongside one whose map key does not match its
	// ClientIpv4. The invalid client is skipped (and reported) while the valid
	// one is still applied.
	err = wg.SetClients(map[netip.Addr]*WgClient{
		validIP: {
			PublicKey:  validKey,
			ClientIpv4: validIP,
			Tun:        tun,
		},
		netip.MustParseAddr("10.0.0.2"): {
			PublicKey:  invalidKey,
			ClientIpv4: netip.MustParseAddr("10.0.0.4"),
			Tun:        tun,
		},
	})
	if err == nil {
		t.Fatal("SetClients did not report the invalid client")
	}

	dev, err := wg.device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("device has %d peers, want 1 (only the valid client)", len(dev.Peers))
	}
	wantKey, err := wgtypes.ParseKey(validKey)
	if err != nil {
		t.Fatalf("parse valid key: %v", err)
	}
	if dev.Peers[0].PublicKey != wantKey {
		t.Fatalf("registered peer key = %v, want the valid client", dev.Peers[0].PublicKey)
	}
}

// AddClients applies peers in batches; all clients across multiple batches
// must land in the device and be recorded with an add time.
func TestWgProxyAddClientsBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := DefaultWgProxySettings()
	settings.ClientBatchSize = 2
	wg := NewWgProxy(ctx, settings)
	defer wg.Close()

	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }
	clients := map[netip.Addr]*WgClient{}
	for i := range 5 {
		_, publicKey, err := WgGenKeyPairStrings()
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		addr := netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)})
		clients[addr] = &WgClient{
			PublicKey:  publicKey,
			ClientIpv4: addr,
			Tun:        tun,
		}
	}

	before := time.Now()
	applied, err := wg.AddClients(clients)
	if err != nil {
		t.Fatalf("AddClients: %v", err)
	}
	if len(applied) != len(clients) {
		t.Fatalf("AddClients applied %d clients, want %d", len(applied), len(clients))
	}
	if count := wg.ClientCount(); count != len(clients) {
		t.Fatalf("ClientCount = %d, want %d", count, len(clients))
	}
	dev, err := wg.device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if len(dev.Peers) != len(clients) {
		t.Fatalf("device has %d peers, want %d", len(dev.Peers), len(clients))
	}
	addTimes := wg.Clients()
	if len(addTimes) != len(clients) {
		t.Fatalf("Clients returned %d entries, want %d", len(addTimes), len(clients))
	}
	for addr, addTime := range addTimes {
		if addTime.Before(before) {
			t.Fatalf("add time for %s predates the AddClients call", addr)
		}
	}
}

// RemoveClients removes peers from the device and respects the addedBefore
// cutoff: clients applied at or after the cutoff are kept.
func TestWgProxyRemoveClients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := NewWgProxy(ctx, DefaultWgProxySettings())
	defer wg.Close()

	tun := func() (WgTun, error) { return newRecordingWgTun(), nil }
	newClient := func(addr netip.Addr) *WgClient {
		_, publicKey, err := WgGenKeyPairStrings()
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		return &WgClient{
			PublicKey:  publicKey,
			ClientIpv4: addr,
			Tun:        tun,
		}
	}

	keepIP := netip.MustParseAddr("10.0.2.1")
	staleIP := netip.MustParseAddr("10.0.2.2")
	if _, err := wg.AddClients(map[netip.Addr]*WgClient{
		keepIP:  newClient(keepIP),
		staleIP: newClient(staleIP),
	}); err != nil {
		t.Fatalf("AddClients: %v", err)
	}

	// a cutoff before the add time must not remove anything (grace window)
	if err := wg.RemoveClients(time.Now().Add(-time.Hour), staleIP); err != nil {
		t.Fatalf("RemoveClients (grace): %v", err)
	}
	if count := wg.ClientCount(); count != 2 {
		t.Fatalf("ClientCount after graced remove = %d, want 2", count)
	}

	// a cutoff after the add time removes the stale client only;
	// removing an unknown addr is a no-op
	unknownIP := netip.MustParseAddr("10.0.2.3")
	if err := wg.RemoveClients(time.Now().Add(time.Hour), staleIP, unknownIP); err != nil {
		t.Fatalf("RemoveClients: %v", err)
	}
	if count := wg.ClientCount(); count != 1 {
		t.Fatalf("ClientCount after remove = %d, want 1", count)
	}
	if _, ok := wg.Clients()[keepIP]; !ok {
		t.Fatal("RemoveClients removed the wrong client")
	}
	dev, err := wg.device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("device has %d peers, want 1", len(dev.Peers))
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

func (self *recordingWgTun) UpdateActivity() bool {
	return true
}

func (self *recordingWgTun) Cancel() {}

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
