package proxy

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/v2026/conn"
	uwgdevice "github.com/urnetwork/userwireguard/v2026/device"
	"github.com/urnetwork/userwireguard/v2026/logger"
	"github.com/urnetwork/userwireguard/v2026/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The on-demand soak: a production-sized index of configured clients, a few
// thousand of which handshake in waves, go idle and are evicted, and come
// back. It logs peers, goroutines and heap after every phase, and the miss
// handler's rate limiting. Off by default:
//
//	WG_SOAK=1 [WG_SOAK_KEYS=3000] [WG_SOAK_CONFIGURED=41000] [WG_SOAK_WAVES=3] \
//	  [WG_SOAK_RATE=1024] [WG_SOAK_BURST=2048] \
//	  go test -run TestWgProxyOnDemandSoak -v -timeout 20m .
//
// Each driver is one userspace client device that takes on identity after
// identity (a new private key and tunnel address), so thousands of distinct
// keys handshake without thousands of client devices.
func TestWgProxyOnDemandSoak(t *testing.T) {
	if os.Getenv("WG_SOAK") == "" {
		t.Skip("set WG_SOAK=1 to run the on-demand peer soak")
	}
	keys := soakEnvInt("WG_SOAK_KEYS", 3000)
	configured := max(keys, soakEnvInt("WG_SOAK_CONFIGURED", 41000))
	waves := soakEnvInt("WG_SOAK_WAVES", 3)
	const driverCount = 16
	const idleTimeout = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	measure := func() (goroutines int, heapMib float64) {
		runtime.GC()
		runtime.GC()
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		return runtime.NumGoroutine(), float64(memStats.HeapAlloc) / (1 << 20)
	}
	start := time.Now()
	report := func(server *onDemandServer, phase string) {
		goroutines, heapMib := measure()
		stats := server.wg.PeerStats()
		t.Logf(
			"t=%5.1fs %-28s peers=%5d goroutines=%6d heap=%7.1fMiB accepted=%d rate_limited=%d refused=%d coalesced=%d handler_timeouts=%d evicted=%d",
			time.Since(start).Seconds(), phase, stats.PeerCount, goroutines, heapMib,
			stats.PeerMiss.Accepted, stats.PeerMiss.RateLimited, stats.PeerMiss.Refused,
			stats.PeerMiss.Coalesced, stats.PeerMiss.HandlerTimeouts, stats.EvictedPeerCount,
		)
	}

	sink := &soakSink{}
	server := startOnDemandWgProxy(t, ctx, func(settings *WgProxySettings) {
		settings.PeerIdleTimeout = idleTimeout
		settings.PeerEvictInterval = time.Second
		settings.PeerMissRatePerSecond = float64(soakEnvInt("WG_SOAK_RATE", int(settings.PeerMissRatePerSecond)))
		settings.PeerMissBurst = soakEnvInt("WG_SOAK_BURST", settings.PeerMissBurst)
		t.Logf("miss handler rate %.0f/s, burst %d", settings.PeerMissRatePerSecond, settings.PeerMissBurst)
	})
	report(server, "listening")

	// the configured index; the first `keys` are the identities that connect
	identities := make([]soakIdentity, keys)
	wgClients := make(map[netip.Addr]*WgClient, configured)
	sinkTun := func() (WgTun, error) { return sink, nil }
	for i := 0; i < configured; i++ {
		privateKey, publicKey, err := WgGenKeyPair()
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}
		ip := netip.AddrFrom4([4]byte{10, byte(64 + i>>16), byte(i >> 8), byte(i)})
		wgClients[ip] = &WgClient{PublicKey: publicKey.String(), ClientIpv4: ip, Tun: sinkTun}
		if i < keys {
			identities[i] = soakIdentity{privateKey: privateKey, ip: ip}
		}
	}
	if _, err := server.wg.AddClients(wgClients); err != nil {
		t.Fatalf("add clients: %v", err)
	}
	report(server, "configured "+strconv.Itoa(configured))

	drivers := make([]*soakDriver, driverCount)
	for i := range drivers {
		drivers[i] = newSoakDriver(t, server)
	}
	report(server, "drivers up")

	for wave := 1; wave <= waves; wave++ {
		sink.reset()
		waveStart := time.Now()
		completed, passes := runSoakWave(ctx, drivers, identities, sink)
		report(server, "wave "+strconv.Itoa(wave)+" connected")
		t.Logf("wave %d: %d/%d identities handshook in %.1fs over %d passes", wave, completed, keys, time.Since(waveStart).Seconds(), passes)
		if completed != keys {
			t.Fatalf("wave %d: %d of %d identities connected", wave, completed, keys)
		}
		if peers := server.wg.PeerCount(); peers < keys {
			t.Fatalf("wave %d: %d peers for %d connected identities", wave, peers, keys)
		}
		// idle: every peer is evicted after the idle bound
		deadline := time.Now().Add(idleTimeout + 30*time.Second)
		for 0 < server.wg.PeerCount() {
			if time.Now().After(deadline) {
				t.Fatalf("wave %d: %d peers were never evicted", wave, server.wg.PeerCount())
			}
			time.Sleep(250 * time.Millisecond)
		}
		report(server, "wave "+strconv.Itoa(wave)+" evicted")
	}
}

type soakIdentity struct {
	privateKey wgtypes.Key
	ip         netip.Addr
}

// soakSink is every client's hosted tun: it records which tunnel addresses
// delivered a packet.
type soakSink struct {
	arrived sync.Map
	count   atomic.Int64
}

func (self *soakSink) reset() {
	self.arrived.Clear()
	self.count.Store(0)
}

func (self *soakSink) has(ip netip.Addr) bool {
	_, ok := self.arrived.Load(ip)
	return ok
}

func (self *soakSink) Active() bool           { return true }
func (self *soakSink) UpdateActivity() bool   { return true }
func (self *soakSink) SetReceive(chan []byte) {}
func (self *soakSink) Cancel()                {}
func (self *soakSink) Send(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	if _, loaded := self.arrived.LoadOrStore(netip.AddrFrom4([4]byte(packet[12:16])), struct{}{}); !loaded {
		self.count.Add(1)
	}
	return true
}

type soakDriver struct {
	device *uwgdevice.Device
	tun    *tuntest.ChannelTUN
}

func newSoakDriver(t *testing.T, server *onDemandServer) *soakDriver {
	t.Helper()
	privateKey, _, err := WgGenKeyPair()
	if err != nil {
		t.Fatalf("generate driver key: %v", err)
	}
	tun := tuntest.NewChannelTUN()
	device := uwgdevice.NewDevice(tun.TUN(), conn.NewDefaultBind(), logger.NewLogger(logger.LogLevelError, "soak: "))
	t.Cleanup(device.Close)
	zeroPort := 0
	if err := device.IpcSet(&wgtypes.Config{
		PrivateKey: &privateKey, ListenPort: &zeroPort, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         server.publicKey,
			Endpoint:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: server.port},
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{{IP: net.IP(onDemandServerIp.AsSlice()), Mask: net.CIDRMask(32, 32)}},
		}},
	}); err != nil {
		t.Fatalf("configure driver: %v", err)
	}
	if err := device.Up(); err != nil {
		t.Fatalf("bring driver up: %v", err)
	}
	return &soakDriver{device: device, tun: tun}
}

// connect takes on the identity and sends one packet as it; it reports
// whether the packet reached the server within the wait. An initiation the
// server rate-limits is abandoned here and retried in a later pass.
func (self *soakDriver) connect(identity soakIdentity, sink *soakSink, wait time.Duration) bool {
	if err := self.device.IpcSet(&wgtypes.Config{PrivateKey: &identity.privateKey}); err != nil {
		return false
	}
	self.tun.Outbound <- udpIPv4Packet(identity.ip, onDemandServerIp, []byte("soak"))
	deadline := time.Now().Add(wait)
	for !sink.has(identity.ip) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

func runSoakWave(ctx context.Context, drivers []*soakDriver, identities []soakIdentity, sink *soakSink) (completed int, passes int) {
	pending := identities
	for 0 < len(pending) && passes < 50 && ctx.Err() == nil {
		passes += 1
		var retryLock sync.Mutex
		retry := []soakIdentity{}
		var wg sync.WaitGroup
		for d, driver := range drivers {
			wg.Add(1)
			go func(d int, driver *soakDriver) {
				defer wg.Done()
				for i := d; i < len(pending); i += len(drivers) {
					if !driver.connect(pending[i], sink, 300*time.Millisecond) {
						retryLock.Lock()
						retry = append(retry, pending[i])
						retryLock.Unlock()
					}
				}
			}(d, driver)
		}
		wg.Wait()
		pending = retry
		if 0 < len(pending) {
			// let the handler call budget refill before the next pass
			time.Sleep(time.Second)
		}
	}
	return int(sink.count.Load()), passes
}

func soakEnvInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && 0 < value {
		return value
	}
	return fallback
}
