package proxy

// On-demand peers (WgProxySettings.PeersOnDemand): AddClients only indexes a
// client; its device peer, with the peer's goroutines and queues, is created
// by the userwireguard miss handler when the client's first handshake
// initiation arrives, and removed after PeerIdleTimeout without a handshake.

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/urnetwork/userwireguard/v2026/conn"
	uwgdevice "github.com/urnetwork/userwireguard/v2026/device"
	"github.com/urnetwork/userwireguard/v2026/logger"
	"github.com/urnetwork/userwireguard/v2026/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var onDemandServerIp = netip.MustParseAddr("10.0.0.1")

func onDemandClientIp(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
}

type onDemandServer struct {
	wg        *WgProxy
	publicKey wgtypes.Key
	port      int
}

// startOnDemandWgProxy listens on loopback with on-demand peers. The
// eviction loop is off unless the caller sets an interval, so tests evict
// deterministically.
func startOnDemandWgProxy(t *testing.T, ctx context.Context, configure func(*WgProxySettings)) *onDemandServer {
	t.Helper()
	serverPrivate, serverPublic, err := WgGenKeyPair()
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}
	settings := DefaultWgProxySettings()
	settings.PrivateKey = serverPrivate.String()
	settings.PeersOnDemand = true
	settings.PeerEvictInterval = 0
	if configure != nil {
		configure(settings)
	}
	wg := NewWgProxy(ctx, settings)
	t.Cleanup(func() {
		_ = wg.Close()
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- wg.ListenAndServe("127.0.0.1", "::1", 0)
	}()
	port := waitForWgListenPort(t, wg, errCh)
	return &onDemandServer{wg: wg, publicKey: serverPublic, port: port}
}

type onDemandClient struct {
	device     *uwgdevice.Device
	tun        *tuntest.ChannelTUN
	privateKey wgtypes.Key
	publicKey  wgtypes.Key
	ip         netip.Addr
	proxyTun   *recordingWgTun
}

func newOnDemandClient(t testing.TB, ip netip.Addr) *onDemandClient {
	t.Helper()
	privateKey, publicKey, err := WgGenKeyPair()
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}
	return &onDemandClient{
		privateKey: privateKey,
		publicKey:  publicKey,
		ip:         ip,
		proxyTun:   newRecordingWgTun(),
	}
}

func (self *onDemandClient) wgClient() *WgClient {
	proxyTun := self.proxyTun
	return &WgClient{
		PublicKey:  self.publicKey.String(),
		ClientIpv4: self.ip,
		Tun: func() (WgTun, error) {
			return proxyTun, nil
		},
	}
}

// start brings up the client's own userspace device, aimed at the server.
func (self *onDemandClient) start(t testing.TB, server *onDemandServer) {
	t.Helper()
	self.tun = tuntest.NewChannelTUN()
	self.device = uwgdevice.NewDevice(
		self.tun.TUN(),
		conn.NewDefaultBind(),
		logger.NewLogger(logger.LogLevelError, "client: "),
	)
	t.Cleanup(self.device.Close)
	zeroPort := 0
	config := wgtypes.Config{
		PrivateKey:   &self.privateKey,
		ListenPort:   &zeroPort,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         server.publicKey,
				Endpoint:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: server.port},
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					{IP: net.IP(onDemandServerIp.AsSlice()), Mask: net.CIDRMask(32, 32)},
				},
			},
		},
	}
	if err := self.device.IpcSet(&config); err != nil {
		t.Fatalf("configure client device: %v", err)
	}
	if err := self.device.Up(); err != nil {
		t.Fatalf("bring client device up: %v", err)
	}
}

// sendUp sends one packet from the client and waits for it at the proxy tun.
func (self *onDemandClient) sendUp(t testing.TB, packet []byte) {
	t.Helper()
	self.tun.Outbound <- packet
	select {
	case got := <-self.proxyTun.sent:
		if !bytes.Equal(got, packet) {
			t.Fatalf("client %s: proxy tun got a different packet", self.ip)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("client %s: packet did not reach the proxy tun", self.ip)
	}
}

// sendDown sends one packet from the proxy side and waits for it at the
// client.
func (self *onDemandClient) sendDown(t *testing.T, packet []byte) {
	t.Helper()
	receive := self.proxyTun.waitReceive(t)
	select {
	case receive <- packet:
	case <-time.After(2 * time.Second):
		t.Fatalf("client %s: could not queue a packet toward the client", self.ip)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-self.tun.Inbound:
			if bytes.Equal(got, packet) {
				return
			}
		case <-deadline:
			t.Fatalf("client %s: packet from the proxy did not arrive", self.ip)
		}
	}
}

func tcpIPv4Packet(src netip.Addr, dst netip.Addr, srcPort uint16, dstPort uint16, syn bool, ack bool, payload []byte) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP(src.AsSlice()),
		DstIP:    net.IP(dst.AsSlice()),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		Ack:     2000,
		SYN:     syn,
		ACK:     ack,
		PSH:     0 < len(payload),
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip,
		tcp,
		gopacket.Payload(payload),
	); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func waitUntil(t *testing.T, timeout time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client registered with AddClients has no device peer until it
// handshakes; its first handshake creates the peer and TCP and UDP move both
// ways.
func TestWgProxyOnDemandClientHandshakesWithoutPeerRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	if count := server.wg.ClientCount(); count != 1 {
		t.Fatalf("ClientCount = %d, want 1", count)
	}
	if count := server.wg.PeerCount(); count != 0 {
		t.Fatalf("AddClients created %d device peers, want 0", count)
	}

	client.start(t, server)
	client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("udp-up")))
	client.sendDown(t, udpIPv4Packet(onDemandServerIp, client.ip, []byte("udp-down")))
	client.sendUp(t, tcpIPv4Packet(client.ip, onDemandServerIp, 40000, 443, true, false, nil))
	client.sendDown(t, tcpIPv4Packet(onDemandServerIp, client.ip, 443, 40000, true, true, nil))
	client.sendUp(t, tcpIPv4Packet(client.ip, onDemandServerIp, 40000, 443, false, true, []byte("GET / HTTP/1.1\r\n\r\n")))
	client.sendDown(t, tcpIPv4Packet(onDemandServerIp, client.ip, 443, 40000, false, true, []byte("HTTP/1.1 200 OK\r\n\r\n")))

	if count := server.wg.PeerCount(); count != 1 {
		t.Fatalf("PeerCount = %d, want 1", count)
	}
	stats := server.wg.PeerStats()
	if stats.PeerMiss.Accepted != 1 {
		t.Fatalf("peer miss stats = %+v, want one acceptance", stats.PeerMiss)
	}
}

// A key the proxy does not know is refused: no peer, no traffic.
func TestWgProxyOnDemandRefusesUnknownKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	known := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{known.ip: known.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	stranger := newOnDemandClient(t, onDemandClientIp(3))
	stranger.start(t, server)
	stranger.tun.Outbound <- udpIPv4Packet(stranger.ip, onDemandServerIp, []byte("stranger"))
	waitUntil(t, 5*time.Second, "the refusal", func() bool {
		return server.wg.PeerStats().PeerMiss.Refused == 1
	})
	if count := server.wg.PeerCount(); count != 0 {
		t.Fatalf("an unknown key created %d peers", count)
	}
}

// After its peer is evicted the same client reconnects through the miss
// handler, and its tun is attached again in both directions.
func TestWgProxyOnDemandEvictedClientReconnects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	client.start(t, server)
	client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("before")))
	client.sendDown(t, udpIPv4Packet(onDemandServerIp, client.ip, []byte("before")))

	if evicted := server.wg.evictIdlePeers(0); evicted != 1 {
		t.Fatalf("evicted %d peers, want 1", evicted)
	}
	if count := server.wg.PeerCount(); count != 0 {
		t.Fatalf("PeerCount after eviction = %d, want 0", count)
	}
	client.proxyTun.stateLock.Lock()
	attached := client.proxyTun.receive != nil
	client.proxyTun.stateLock.Unlock()
	if attached {
		t.Fatal("the evicted client's tun is still attached to the wg receive channel")
	}

	// the client's next handshake (its rekey timer would start one; here it
	// is forced) goes through the miss handler again
	clientPeer := client.device.LookupPeer(uwgdevice.NoisePublicKey(server.publicKey))
	if clientPeer == nil {
		t.Fatal("client has no server peer")
	}
	clientPeer.ExpireCurrentKeypairs()
	client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("after")))
	client.sendDown(t, udpIPv4Packet(onDemandServerIp, client.ip, []byte("after")))
	stats := server.wg.PeerStats()
	if stats.PeerMiss.Accepted != 2 || stats.EvictedPeerCount != 1 {
		t.Fatalf("peer stats = %+v, want 2 acceptances and 1 eviction", stats)
	}
}

// The eviction loop removes a peer that has not handshaken within the idle
// bound.
func TestWgProxyOnDemandEvictionLoopRemovesIdlePeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, func(settings *WgProxySettings) {
		settings.PeerIdleTimeout = 300 * time.Millisecond
		settings.PeerEvictInterval = 50 * time.Millisecond
	})
	client := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	client.start(t, server)
	client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("once")))
	waitUntil(t, 5*time.Second, "the idle peer to be evicted", func() bool {
		return server.wg.PeerCount() == 0
	})
}

// With many configured clients only the ones that handshake get peers, and
// so goroutines and queues. The eager mode is measured alongside to show the
// measurement sees the difference.
func TestWgProxyOnDemandOnlyActiveClientsCreatePeers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds thousands of peers")
	}
	const configured = 2000
	const active = 3

	measure := func() (goroutines int, heap uint64) {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return runtime.NumGoroutine(), stats.HeapAlloc
	}
	configure := func(t *testing.T, onDemand bool) (*onDemandServer, []*onDemandClient, int, int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		server := startOnDemandWgProxy(t, ctx, func(settings *WgProxySettings) {
			settings.PeersOnDemand = onDemand
		})
		clients := make([]*onDemandClient, configured)
		wgClients := map[netip.Addr]*WgClient{}
		for i := range clients {
			clients[i] = newOnDemandClient(t, onDemandClientIp(i+2))
			wgClients[clients[i].ip] = clients[i].wgClient()
		}
		goroutinesBefore, heapBefore := measure()
		if _, err := server.wg.AddClients(wgClients); err != nil {
			t.Fatalf("add clients: %v", err)
		}
		goroutinesAfter, heapAfter := measure()
		return server, clients, goroutinesAfter - goroutinesBefore, int64(heapAfter) - int64(heapBefore)
	}

	t.Run("eager", func(t *testing.T) {
		server, _, goroutines, heap := configure(t, false)
		t.Logf("eager: %d configured -> %d peers, +%d goroutines, %+d heap bytes", configured, server.wg.PeerCount(), goroutines, heap)
		if server.wg.PeerCount() != configured || goroutines < 2*configured {
			t.Fatalf("eager registration made %d peers and %d goroutines, want %d and at least %d", server.wg.PeerCount(), goroutines, configured, 2*configured)
		}
	})

	t.Run("on demand", func(t *testing.T) {
		server, clients, goroutines, heap := configure(t, true)
		t.Logf("on demand: %d configured -> %d peers, +%d goroutines, %+d heap bytes", configured, server.wg.PeerCount(), goroutines, heap)
		if server.wg.PeerCount() != 0 || 20 < goroutines {
			t.Fatalf("on-demand registration made %d peers and %d goroutines, want 0 and at most 20", server.wg.PeerCount(), goroutines)
		}
		if 8<<20 < heap {
			t.Fatalf("on-demand registration grew the heap by %d bytes, want at most 8 MiB", heap)
		}
		for _, client := range clients[:active] {
			client.start(t, server)
			client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("active")))
		}
		if count := server.wg.PeerCount(); count != active {
			t.Fatalf("PeerCount = %d, want the %d active clients", count, active)
		}
	})
}

// PeerStatuses follows the live peers, not the configured clients: its
// result and its allocations do not grow with the configuration.
func TestWgProxyOnDemandPeerStatusesFollowLivePeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	addConfigured := func(from int, n int) {
		wgClients := map[netip.Addr]*WgClient{}
		for i := from; i < from+n; i++ {
			client := newOnDemandClient(t, onDemandClientIp(i))
			wgClients[client.ip] = client.wgClient()
		}
		if _, err := server.wg.AddClients(wgClients); err != nil {
			t.Fatalf("add clients: %v", err)
		}
	}
	live := newOnDemandClient(t, onDemandClientIp(1))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{live.ip: live.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	live.start(t, server)
	live.sendUp(t, udpIPv4Packet(live.ip, onDemandServerIp, []byte("live")))

	addConfigured(2, 300)
	statuses, err := server.wg.PeerStatuses()
	if err != nil {
		t.Fatalf("peer statuses: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("PeerStatuses returned %d entries with 301 configured and 1 live, want 1", len(statuses))
	}
	status := statuses[live.ip]
	if status == nil || status.Endpoint == nil || status.LastHandshake.IsZero() || status.PublicKey != live.publicKey.String() {
		t.Fatalf("live status = %+v, want its key, endpoint and handshake", status)
	}
	smallAllocs := testing.AllocsPerRun(20, func() {
		_, _ = server.wg.PeerStatuses()
	})
	addConfigured(400, 3000)
	largeAllocs := testing.AllocsPerRun(20, func() {
		_, _ = server.wg.PeerStatuses()
	})
	t.Logf("PeerStatuses allocations: %.0f with 301 configured, %.0f with 3301", smallAllocs, largeAllocs)
	if smallAllocs+2 < largeAllocs {
		t.Fatalf("PeerStatuses allocations grew from %.0f to %.0f with configured clients", smallAllocs, largeAllocs)
	}
}

// Removing a connected client removes its live peer and tears down its tun;
// its next initiation is refused.
func TestWgProxyOnDemandRemoveClientsRemovesLivePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	client := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	client.start(t, server)
	client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("before")))

	if err := server.wg.RemoveClients(time.Now().Add(time.Hour), client.ip); err != nil {
		t.Fatalf("remove clients: %v", err)
	}
	if server.wg.ClientCount() != 0 || server.wg.PeerCount() != 0 {
		t.Fatalf("after removal: %d clients and %d peers, want none", server.wg.ClientCount(), server.wg.PeerCount())
	}
	clientPeer := client.device.LookupPeer(uwgdevice.NoisePublicKey(server.publicKey))
	clientPeer.ExpireCurrentKeypairs()
	client.tun.Outbound <- udpIPv4Packet(client.ip, onDemandServerIp, []byte("after"))
	waitUntil(t, 5*time.Second, "the removed key to be refused", func() bool {
		return server.wg.PeerStats().PeerMiss.Refused == 1
	})
	if server.wg.PeerCount() != 0 {
		t.Fatal("a removed client got a peer back")
	}
}

// A client whose key changes at the same address loses the old key's live
// peer; the new key connects on demand and the old one is refused.
func TestWgProxyOnDemandRekeyedClientReplacesPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startOnDemandWgProxy(t, ctx, nil)
	oldClient := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{oldClient.ip: oldClient.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	oldClient.start(t, server)
	oldClient.sendUp(t, udpIPv4Packet(oldClient.ip, onDemandServerIp, []byte("old")))

	newClient := newOnDemandClient(t, oldClient.ip)
	if _, err := server.wg.AddClients(map[netip.Addr]*WgClient{newClient.ip: newClient.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	if server.wg.PeerCount() != 0 {
		t.Fatal("the old key's peer survived the key change")
	}
	newClient.start(t, server)
	newClient.sendUp(t, udpIPv4Packet(newClient.ip, onDemandServerIp, []byte("new")))
	if server.wg.PeerCount() != 1 {
		t.Fatalf("PeerCount = %d, want the new key's peer", server.wg.PeerCount())
	}
}

// The deploy handoff reaches clients first: seeding an exported endpoint
// creates the peer, so the server-side initiation has a peer to send from.
// A client added with an endpoint gets its peer at once for the same reason.
func TestWgProxyOnDemandHandoffCreatesSeededPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ctxA, cancelA := context.WithCancel(ctx)
	serverA := startOnDemandWgProxy(t, ctxA, nil)
	client := newOnDemandClient(t, onDemandClientIp(2))
	if _, err := serverA.wg.AddClients(map[netip.Addr]*WgClient{client.ip: client.wgClient()}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	client.start(t, serverA)
	client.sendUp(t, udpIPv4Packet(client.ip, onDemandServerIp, []byte("to-a")))

	statuses, err := serverA.wg.PeerStatuses()
	if err != nil {
		t.Fatalf("peer statuses: %v", err)
	}
	status := statuses[client.ip]
	if status == nil || status.Endpoint == nil || status.LastHandshake.IsZero() {
		t.Fatalf("export = %+v, want an endpoint and a handshake", status)
	}
	cancelA()
	_ = serverA.wg.Close()

	// server B takes the same key and port; the client still has its old
	// session and only answers what B sends first
	serverB := startOnDemandWgProxyWithKey(t, ctx, serverA, nil)
	tunB := newRecordingWgTun()
	clientB := &WgClient{
		PublicKey:  client.publicKey.String(),
		ClientIpv4: client.ip,
		Tun: func() (WgTun, error) {
			return tunB, nil
		},
	}
	if _, err := serverB.wg.AddClients(map[netip.Addr]*WgClient{client.ip: clientB}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	if serverB.wg.PeerCount() != 0 {
		t.Fatal("a client without an endpoint got a peer before handshaking")
	}
	seeded, err := serverB.wg.SeedEndpoints(map[netip.Addr]*net.UDPAddr{client.ip: status.Endpoint})
	if err != nil || seeded != 1 {
		t.Fatalf("seeded %d endpoints (err %v), want 1", seeded, err)
	}
	if serverB.wg.PeerCount() != 1 {
		t.Fatal("seeding an endpoint did not create the peer")
	}
	if err := serverB.wg.InitiateHandshake(client.ip); err != nil {
		t.Fatalf("initiate handshake: %v", err)
	}
	packet := udpIPv4Packet(client.ip, onDemandServerIp, []byte("to-b"))
	deadline := time.After(10 * time.Second)
	for {
		client.tun.Outbound <- packet
		select {
		case got := <-tunB.sent:
			if !bytes.Equal(got, packet) {
				t.Fatal("server B got a different packet")
			}
			goto handedOff
		case <-time.After(250 * time.Millisecond):
		case <-deadline:
			t.Fatal("traffic did not resume on server B")
		}
	}
handedOff:
	statuses, err = serverB.wg.PeerStatuses()
	if err != nil || statuses[client.ip] == nil || statuses[client.ip].LastHandshake.IsZero() {
		t.Fatalf("server B statuses = %+v (err %v), want the re-established client", statuses, err)
	}

	// a client registered with an endpoint is reachable at once
	other := newOnDemandClient(t, onDemandClientIp(3))
	withEndpoint := other.wgClient()
	withEndpoint.Endpoint = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if _, err := serverB.wg.AddClients(map[netip.Addr]*WgClient{other.ip: withEndpoint}); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	if serverB.wg.PeerCount() != 2 {
		t.Fatalf("PeerCount = %d, want the client added with an endpoint to have a peer", serverB.wg.PeerCount())
	}
	if err := serverB.wg.InitiateHandshake(other.ip); err != nil {
		t.Fatalf("initiate toward a client added with an endpoint: %v", err)
	}
}

// startOnDemandWgProxyWithKey brings up a replacement on another server's
// key and port.
func startOnDemandWgProxyWithKey(t *testing.T, ctx context.Context, previous *onDemandServer, configure func(*WgProxySettings)) *onDemandServer {
	t.Helper()
	privateKey := previous.wg.settings.PrivateKey
	settings := DefaultWgProxySettings()
	settings.PrivateKey = privateKey
	settings.PeersOnDemand = true
	settings.PeerEvictInterval = 0
	if configure != nil {
		configure(settings)
	}
	wg := NewWgProxy(ctx, settings)
	t.Cleanup(func() {
		_ = wg.Close()
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- wg.ListenAndServe("127.0.0.1", "::1", previous.port)
	}()
	port := waitForWgListenPort(t, wg, errCh)
	return &onDemandServer{wg: wg, publicKey: previous.publicKey, port: port}
}
