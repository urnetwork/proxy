package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// TestWgProxyClientTrickleRouting creates many wg clients in a steady trickle
// (AddClients, which programs peers into the real wg device) while concurrently
// routing packets for the already-added set (WgProxy.Write -> activateClient).
//
// It is the regression guard for the wg-proxy locking rework: control-plane peer
// programming (device.IpcSet, held under controlLock) must not block the data
// path (activateClient, which takes only a brief read lock). The test asserts
// that routing keeps succeeding for already-added clients while new clients are
// still being created, and that every client routes at the end.
//
// Routing here means activateClient resolves the client and its tun accepts the
// packet — the tuns are lightweight mocks, so this exercises the wg-proxy
// dispatch + locking at scale, not a real egress device (impossible at 32k).
//
// Default client count is 32768 (reduced under -race to keep the data-race scan
// bounded — see wgPerfDefaultClients); override with WG_PERF_CLIENTS. Skipped
// under -short.
func TestWgProxyClientTrickleRouting(t *testing.T) {
	if testing.Short() {
		t.Skip("perf test")
	}

	target := wgPerfDefaultClients
	if v := os.Getenv("WG_PERF_CLIENTS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("invalid WG_PERF_CLIENTS=%q", v)
		}
		target = n
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	settings := DefaultWgProxySettings()
	// silence the per-peer add logging at this scale
	settings.Log = connect.NewNoopLogger()
	settings.ClientBatchSize = 64
	wg := NewWgProxy(ctx, settings)
	t.Cleanup(func() { _ = wg.Close() })

	// pre-generate clients off the measured path: a unique addr + wg keypair + a
	// counting mock tun + a prebuilt packet per client. Generating the real wg
	// keypairs is the bulk of setup.
	type clientSpec struct {
		addr   netip.Addr
		client *WgClient
		tun    *countingWgTun
		packet []byte
	}
	dst := netip.MustParseAddr("1.1.1.1")
	genStart := time.Now()
	specs := make([]clientSpec, target)
	for i := range specs {
		_, publicKey, err := WgGenKeyPairStrings()
		if err != nil {
			t.Fatalf("generate keypair %d: %v", i, err)
		}
		addr := wgPerfAddr(i)
		tun := &countingWgTun{}
		specs[i] = clientSpec{
			addr: addr,
			tun:  tun,
			client: &WgClient{
				PublicKey:  publicKey,
				ClientIpv4: addr,
				Tun:        func() (WgTun, error) { return tun, nil },
			},
			packet: udpIPv4Packet(addr, dst, []byte("route")),
		}
	}
	fmt.Printf("[perf]generated %d clients in %v\n", target, time.Since(genStart).Round(time.Millisecond))

	var (
		added         atomic.Int64 // number of specs added so far (in order)
		routeOK       atomic.Int64
		routeFail     atomic.Int64
		maxRouteNanos atomic.Int64
		addFailures   atomic.Int64
		stop          atomic.Bool
	)

	route := func(spec *clientSpec) bool {
		t0 := time.Now()
		count, err := wg.Write([][]byte{spec.packet}, 0)
		lat := time.Since(t0).Nanoseconds()
		for {
			cur := maxRouteNanos.Load()
			if lat <= cur || maxRouteNanos.CompareAndSwap(cur, lat) {
				break
			}
		}
		return err == nil && count == 1
	}

	// routers: continuously route a random already-added client while the
	// trickle runs, so routing genuinely overlaps client creation
	routerCount := max(2, runtime.NumCPU())
	var routers sync.WaitGroup
	for r := 0; r < routerCount; r++ {
		routers.Add(1)
		go func(seed int64) {
			defer routers.Done()
			rng := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				n := int(added.Load())
				if n == 0 {
					runtime.Gosched()
					continue
				}
				if route(&specs[rng.Intn(n)]) {
					routeOK.Add(1)
				} else {
					routeFail.Add(1)
				}
			}
		}(int64(r) + 1)
	}

	// trickle: add clients in small groups with a short pause, simulating a
	// steady arrival rate concurrent with routing
	trickleStart := time.Now()
	const groupSize = 32
	for start := 0; start < target; start += groupSize {
		end := min(start+groupSize, target)
		group := make(map[netip.Addr]*WgClient, end-start)
		for i := start; i < end; i++ {
			group[specs[i].addr] = specs[i].client
		}
		applied, err := wg.AddClients(group)
		if err != nil || len(applied) != len(group) {
			addFailures.Add(1)
		}
		// publish only after AddClients has recorded the group, so routers never
		// pick a client that is not yet routable
		added.Store(int64(end))
		time.Sleep(time.Millisecond)
	}
	trickleDur := time.Since(trickleStart)

	// let routers run briefly against the full set, then stop them
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	routers.Wait()

	fmt.Printf("[perf]trickled %d clients in %v (%.0f clients/s)\n",
		target, trickleDur.Round(time.Millisecond), float64(target)/trickleDur.Seconds())
	fmt.Printf("[perf]routed %d ok / %d fail during trickle, max route latency %v\n",
		routeOK.Load(), routeFail.Load(), time.Duration(maxRouteNanos.Load()).Round(time.Microsecond))

	if addFailures.Load() != 0 {
		t.Fatalf("%d AddClients groups failed", addFailures.Load())
	}
	if count := wg.ClientCount(); count != target {
		t.Fatalf("ClientCount = %d, want %d", count, target)
	}
	if routeFail.Load() != 0 {
		t.Fatalf("%d routes failed for already-added clients during the trickle", routeFail.Load())
	}
	if routeOK.Load() == 0 {
		t.Fatal("no routes succeeded during the trickle (routing did not run concurrently with creation)")
	}
	// stall canary: a route blocked behind control-plane peer programming would
	// spike here. The bound is generous — the point is to catch a hard stall or
	// deadlock, not to assert a tight latency.
	if maxLat := time.Duration(maxRouteNanos.Load()); maxLat > 5*time.Second {
		t.Fatalf("max route latency %v during trickle indicates the data path stalled behind client creation", maxLat)
	}

	// final sweep: every client must route
	sweepStart := time.Now()
	failed := 0
	for i := range specs {
		if !route(&specs[i]) {
			failed++
		}
	}
	if failed != 0 {
		t.Fatalf("final sweep: %d/%d clients did not route", failed, target)
	}
	fmt.Printf("[perf]final sweep: all %d clients routed in %v\n", target, time.Since(sweepStart).Round(time.Millisecond))

	// every client's tun must have received at least its sweep packet
	missing := 0
	for i := range specs {
		if specs[i].tun.sent.Load() == 0 {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("%d/%d client tuns never received a packet", missing, target)
	}
}

// countingWgTun is a minimal WgTun that always accepts packets and counts them.
// It stands in for a real proxy device so the trickle test can exercise the
// wg-proxy dispatch + locking at 32k clients without 32k real egress devices.
type countingWgTun struct {
	sent atomic.Int64
}

func (self *countingWgTun) Active() bool         { return true }
func (self *countingWgTun) UpdateActivity() bool { return true }
func (self *countingWgTun) Cancel()              {}

func (self *countingWgTun) Send(packet []byte) bool {
	self.sent.Add(1)
	return true
}

func (self *countingWgTun) SetReceive(receive chan []byte) {}

// wgPerfAddr maps a client index to a unique ipv4 in 10.0.0.0/8 (10.0.0.1 + i).
func wgPerfAddr(i int) netip.Addr {
	v := uint32(0x0A000000) + uint32(i) + 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
