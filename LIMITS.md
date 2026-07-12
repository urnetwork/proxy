# Proxy limits

What one proxy process can actually hold, measured — not estimated — plus the
configured caps that bound it, and how to regenerate every number here.

Measured on darwin/arm64, Go 1.26, 10 cores. Absolute values will shift on other
hardware; the **per-client marginal cost** is the number that travels.

---

## 1. Concurrent clients per 8GiB process

The headline: **how many concurrent clients fit in the 8GiB we allocate per proxy
process.**

| proxy | per client | clients per 8GiB | what actually binds first |
|-------|-----------|------------------|---------------------------|
| **socks CONNECT** | 25.3 KiB | **~330,000** | memory |
| **http CONNECT** | 33.6 KiB | **~249,000** | memory |
| **wireguard** (registered peer) | 23.8 KiB | ~351,000 | **`MaxPeers` = 65,536**, not memory (65k peers ≈ 1.5GiB) |
| **socks UDP ASSOCIATE** | 8.7 KiB per *flow* idle; **142 KiB backlogged** (gVisor) | **~155,000** typical (4 idle flows) / **~923** worst case (64 backlogged flows) | `AssociateMaxFlows` |

`fd` is never the binding constraint for the TCP paths at these numbers (2 fds
per client), but the process needs `RLIMIT_NOFILE` well above `2 x clients`.

### socks CONNECT (idle tunnels)

```
   clients          rss         heap        stack   goroutines     rss/client
      2000     79.8 MiB     25.9 MiB     24.4 MiB         4019              -
      5000    152.4 MiB     59.3 MiB     59.5 MiB        10019       24.8 KiB
     10000    278.5 MiB    116.2 MiB    118.1 MiB        20019       25.4 KiB
     20000    528.9 MiB    230.1 MiB    235.6 MiB        40019       25.5 KiB
     30000    770.5 MiB    339.6 MiB    353.1 MiB        60019       25.3 KiB
```
marginal **25.3 KiB/client**, 30.5 MiB fixed baseline → **~330,000 per 8GiB**

### http CONNECT (idle tunnels)

```
   clients          rss         heap        stack   goroutines     rss/client
      2000     97.3 MiB     43.4 MiB     24.3 MiB         4019              -
      5000    190.6 MiB     96.0 MiB     59.7 MiB        10019       31.8 KiB
     10000    366.1 MiB    203.1 MiB    118.2 MiB        20019       34.4 KiB
     20000    693.8 MiB    396.3 MiB    235.5 MiB        40019       33.9 KiB
     30000   1015.0 MiB    578.0 MiB    354.3 MiB        60019       33.6 KiB
```
marginal **33.6 KiB/client**, 31.7 MiB fixed baseline → **~249,000 per 8GiB**

http costs more than socks for the same tunnel because `net/http` carries its own
per-connection request/response machinery on top of the same relay.

### wireguard (registered peers)

```
   clients          rss         heap        stack   goroutines     rss/client
      2000     75.1 MiB     46.8 MiB      0.7 MiB           38              -
      5000    142.9 MiB    113.1 MiB      0.7 MiB           38       23.2 KiB
     10000    260.7 MiB    224.0 MiB      0.7 MiB           38       23.8 KiB
     20000    493.5 MiB    446.0 MiB      0.7 MiB           38       23.8 KiB
```
marginal **23.8 KiB/peer** → ~351,000 per 8GiB, **but the device caps at
`MaxPeers` = 65,536 first**. 65,536 peers is only ~1.5GiB, so wireguard is
peer-limited, never memory-limited. Note the goroutine count: **flat at 38** —
peers cost no goroutines, which is why this path is so much cheaper than it looks.

**This measures a REGISTERED peer only.** An *active* client additionally carries
a tun — a gVisor netstack owned by `connect`, not by this repo — which dwarfs the
23.8 KiB peer record. Active-client capacity has to be sized separately.

### socks UDP ASSOCIATE

```
     flows          rss         heap   goroutines      (200 associations)
         0     30.1 MiB      3.2 MiB          418
       200     33.5 MiB      4.3 MiB          618
       400     35.1 MiB      5.1 MiB          818
       800     37.8 MiB      6.6 MiB         1218
      1600     43.8 MiB      9.7 MiB         2018
      3200     57.4 MiB     16.1 MiB         3618
```

| | rss | heap |
|---|---|---|
| per association | 19.2 KiB | 6.2 KiB |
| **per flow** | **8.7 KiB** | **4.1 KiB** |

Associate is not one number, because a single client holds many flows. At the
default `AssociateMaxFlows` = 512:

At the default `AssociateMaxFlows` = **64** (bittorrent and file sharing are
blocked, and nothing else legitimately needs more than 64 concurrent UDP
destinations):

- one client at its cap holds ~0.5 MiB of proxy memory, plus its gVisor endpoints
- **~155,000 clients per 8GiB at a typical 4 flows each**
- **~923 clients per 8GiB if every client fills its NAT table with backlogged
  flows** — see the gVisor table below, which is what actually binds

**`AssociateMaxFlows` is a memory-exposure knob, not just a fairness knob.**

**This got 18x cheaper by bounding the datagram size.** The relay used to size its
per-flow buffer for the theoretical maximum UDP datagram (65,507 B), holding
**73.4 KiB of heap per flow** and capping the worst case at ~254 clients. It now
carries a 2kib MTU and DROPS anything larger, so a flow holds a 2.3 KiB buffer and
**4.1 KiB of heap**. The flow's goroutine stack, not its buffer, is now the
dominant per-flow cost.

Bounding the size is not just "use a smaller buffer" — see `socks5/associate.go`.
A UDP read into a buffer smaller than the datagram silently discards the tail and
reports success, so a relay that simply shrinks its buffer starts forwarding
truncated (corrupted) payloads with nothing anywhere reporting a problem. The
relay reads into one byte MORE than the largest datagram it accepts, so a read
that fills the buffer is known to be oversize and is dropped. A payload-length
check is needed on top of that, because the SOCKS header ranges from 10 to 262
bytes, so a small header can carry an oversize payload and still fit.

**In production a flow also costs a gVisor UDP endpoint, and that — not our
buffer — is the real cost.** Measured (`connect/tun_capacity_test.go`), a
BACKLOGGED flow costs what its gVisor receive buffer allows:

| udp buffer | backlogged flow | 64 flows | clients per 8GiB |
|---|---|---|---|
| 1 MiB (the old default) | 576 KiB | 36.0 MiB | ~227 |
| 128 KiB | 277 KiB | 17.3 MiB | ~472 |
| **64 KiB (now)** | **142 KiB** | **8.9 MiB** | **~923** |
| 32 KiB (gvisor's own default) | 76 KiB | 4.7 MiB | ~1,726 |

`connect`'s default sizes udp endpoints at `MemoryScaledByteCount(mib(1),
kib(128))` — and `memoryScale()` only ever scales *down*, for constrained devices,
so a server got the full **1 MiB per direction**. That is right for a single-user
device, where a deep queue buys throughput and there is one of them. It is wrong
here: the server builds **one stack per client** and one udp endpoint per flow, so
the buffer is multiplied by clients x flows, and what matters is per-endpoint
memory, not per-endpoint throughput. The associate relay caps datagrams at 2kib
and drains each flow with a dedicated reader, so it cannot even use a 500-datagram
queue.

`server/proxy/proxy_device.go` now sets **64 KiB** for the proxy's per-client tuns
(the sdk client keeps the large buffers). That is a **4x** improvement in the
associate worst case and still absorbs ~45 MTU-sized datagrams of burst. 32 KiB
would give 7.6x if it is ever worth pushing.

---

## 1a. Active proxies per instance — the number to scale from

An **active proxy** is one `ProxyDevice`: its own **connect Client** *and* its own
**gVisor stack**, plus whatever tunnels and udp flows that client carries. Both
baselines multiply by every active proxy, so 1-2k proxies means 1-2k Clients and
1-2k stacks.

Measured (`connect/tun_capacity_test.go`, `TestActiveProxyCapacity`) with the
shipped buffer settings — tcp keeps the full 1MiB window, udp is capped at 128KiB:

| term | cost |
|------|------|
| connect Client (idle) | 35.8 KiB |
| gVisor stack (idle) | 61.2 KiB |
| **baseline per active proxy** | **98.7 KiB** |
| + per tcp tunnel, idle | 5.8 KiB |
| + per tcp tunnel, **backlogged** | **684.5 KiB** |
| + per udp flow, idle | ~0 (below the measurement's noise floor) |
| + per udp flow, **backlogged** | **271.9 KiB** |

**The active fraction decides everything.** An idle tunnel is ~6 KiB; a backlogged
one is ~685 KiB — **over 100x**. Capacity is therefore far more sensitive to what
fraction of a client's connections are active at one instant than to how many
connections exist. The working rule is **20% active**:

| mix (tunnels / udp flows) | per proxy | active proxies per 8GiB |
|---------------------------|-----------|-------------------------|
| light (10 / 4) | 1.7 MiB | ~4,800 |
| **typical (25 / 8)** | **4.0 MiB** | **~2,000** |
| heavy (60 / 32) | 10.2 MiB | ~800 |
| saturated (100 / 64 = the udp cap) | 17.5 MiB | ~470 |

### Read this before sizing instances

**At 2,000 active proxies on a typical mix, 8GiB is exactly consumed** (2,000 x
4.0 MiB = 8.0 GiB). There is no headroom at the top of the stated 1-2k range. That
is fine as a plan and dangerous as an assumption: a shift in the active fraction,
or a drift toward the heavy column, puts the instance over.

Concretely:

- **1,000 active proxies: comfortable** (~4 GiB at a typical mix, half the budget).
- **2,000 active proxies: at the line.** Any of {a heavier mix, an active fraction
  above 20%, the connect Client costing more under traffic than the idle 35.8 KiB
  measured here} pushes it over.

Two inputs are assumed rather than measured, and both move this number:

1. **The 20% active fraction.** It is a rule of thumb, not an observation. It is
   the single highest-leverage thing to instrument in production, because it swings
   capacity across the whole table above.
2. **The connect Client was measured IDLE** — no transports attached, no active
   send/receive sequences. It is a per-proxy baseline term, so if a Client carrying
   traffic costs materially more, every row moves.

### Why tcp costs so much, and why that is the right call

A backlogged tcp tunnel costs 688 KiB because it holds a grown 1MiB window (plus
gVisor's ~2x packet-buffer overhead over the accounted payload limit). Capping the
window would cut that in proportion — 128KiB gives ~96 KiB per backlogged tunnel,
a 7x saving.

**We do not cap it,** because tcp throughput is bounded by `window / RTT`:

| RTT | max single-connection throughput at a 128KiB window |
|-----|-----------------------------------------------------|
| 20 ms | ~52 Mbps |
| 50 ms | ~21 Mbps |
| 100 ms | ~10 Mbps |
| 200 ms | ~5 Mbps |

Capping the window to save memory would directly cap user-visible speed on exactly
the high-latency paths a VPN runs over. Memory is cheaper than throughput here, so
tcp keeps the 1MiB default and we scale instances instead.

**udp has no such trade-off and IS capped.** The socks associate relay bounds
datagrams at 2kib and drains every flow with a dedicated reader, so it cannot use a
deep queue at all: the 1MiB default was ~500 datagrams of headroom a prompt reader
never fills. `server/proxy/proxy_device.go` sets 128KiB — still ~90 MTU-sized
datagrams of burst — taking a backlogged flow from 576 KiB to 272 KiB for free.

### Measuring this correctly is subtle

Two mistakes make these numbers look far better than they are, and both were made
and corrected here:

- **Loopback RTT is ~0**, so gVisor's window auto-tuning never grows the buffer
  near Max and a naive loopback measurement reports a fraction of the real
  backlogged cost. `TestTunTcpWindowCeiling` forces `Default = Max` to show what a
  grown window on a real path actually costs: **190 KiB -> 1400 KiB** per loopback
  connection as the window goes 128KiB -> 1MiB.
- **A loopback connection holds BOTH endpoints.** In production the far end lives
  in a remote kernel, not our heap, so a production tunnel costs about half the
  loopback figure. The tables above are per-tunnel (halved); the raw loopback
  numbers are not.


---

## 2. Configured caps

The limits the code imposes, and where they live.

| limit | value | where |
|-------|-------|-------|
| wireguard peers per device | 65,536 (`1<<16`) | `userwireguard/device/constants.go` → `proxy.MaxClients` |
| wireguard peer batch per device write | 256 | `WgProxySettings.ClientBatchSize` |
| UDP flows per association | **64** | `socks5.Settings.AssociateMaxFlows` |
| UDP flow idle timeout | 60s | `socks5.Settings.AssociateIdleTimeout` |
| UDP max datagram (payload; larger is DROPPED, never truncated) | 2,048 B | `socks5.Settings.MaxDatagramSize` |
| UDP buffer (per flow, held for its life) | 2,311 B | `socks5.MaxUdpBufferSize` |
| relay copy buffer (per direction, held for the conn's life) | 2,048 B | `relay.BufferSize` |
| goroutines per TCP client | **2** | `relay.Bidi` + the per-conn serve goroutine |
| socks handshake timeout | 30s | `socks5.Settings.HandshakeTimeout` |
| http max request body buffered | 2 MiB | `HttpProxy.MaxHttpBodyBytes` |
| http CONNECT early-bytes buffer | 64 KiB | `maxEarlyClientBytes` |
| http dial-retry backoff floor | 1s | `minProxyConnectTimeout` |

Defaults live in `socks5.DefaultSettings`, `proxy.DefaultSocksProxySettings` and
`proxy.DefaultHttpProxySettings`: **read 30s, write 15s**, connect 30min. Read
exceeds write deliberately — a read is an idle tunnel waiting for traffic, while a
write that cannot drain means the peer stopped reading.

The read timeout is load-bearing in two ways. It tears down an idle tunnel, which
is intentional: a WAN connection with no heartbeat is going to be dropped by the
network anyway. And it gates SOCKS half-close, because once EOF has been read TCP
cannot distinguish a half-close from a vanished peer, so the surviving direction
can only be bounded by an idle timeout.

### The two knobs that dominate TCP capacity

1. **`relay.BufferSize` (2 KiB).** A buffer is held for a relay direction's whole
   life, so a tunnel costs `2 x BufferSize`. At the 32 KiB `io.Copy` default that
   is 64 KiB/tunnel instead of 4 KiB — worth roughly **3x** of the capacity above.
2. **Goroutines per client.** Stacks were the *largest* per-connection item,
   bigger than buffers. Each tunnel used to carry 4 (socks) / 5 (http) goroutines;
   two were removable — the cancellation watcher became a `context.AfterFunc`
   (which holds no goroutine while waiting) and one copy direction now runs on the
   caller's goroutine. Now **2 per client**, worth +29% (socks) / +35% (http).

---

## 3. How to regenerate

```sh
# all four proxy types; takes a few minutes and opens tens of thousands of sockets
ulimit -n 200000
PROXY_CAPACITY=1 go test -count=1 -v -timeout 30m -run TestCapacity ./

# one at a time
PROXY_CAPACITY=1 go test -v -timeout 20m -run TestCapacitySocksConnect ./
PROXY_CAPACITY=1 go test -v -timeout 20m -run TestCapacityHttpConnect ./
PROXY_CAPACITY=1 go test -v -timeout 20m -run TestCapacityWgPeers ./
PROXY_CAPACITY=1 go test -v -timeout 20m -run TestCapacitySocksAssociate ./
```

The harness is `capacity_test.go`. It is skipped unless `PROXY_CAPACITY` is set,
so it never runs in normal CI.

**Never run it under `-race`.** The detector multiplies per-goroutine memory and
the numbers become meaningless.

### How it works, and why it is built that way

- **The proxy runs in a CHILD process** and the parent measures its RSS
  (`ps -o rss=`). This is the whole point: hosting the test client and the backend
  in the same process as the proxy folds their memory into the measurement and
  roughly triples it. `TestMain` re-execs the test binary with
  `PROXY_CAPACITY_ROLE` set; the child serves one proxy and answers `GC` / `STATS`
  / `PEERS` commands on stdin.
- **Sampling forces `runtime.GC()` + `debug.FreeOSMemory()` first**, so RSS
  reflects live memory rather than garbage the runtime has not returned yet.
- **We fit the MARGINAL cost** — `(rss(n2) - rss(n1)) / (n2 - n1)` — not
  `rss / n`. The marginal cost excludes the Go runtime's fixed baseline (~30 MiB),
  which is what makes extrapolating to 8GiB legitimate. Check the `rss/client`
  column is flat across the ramp; if it is not, the model is not linear and the
  extrapolation is void.
- **Most legs run over unix sockets, not loopback TCP.** Ephemeral ports are a
  HOST-wide resource — only ~16,384 — and each client needs two (client→proxy and
  proxy→backend), which caps a TCP ramp at ~8k clients: far too few to extrapolate
  from. Unix sockets use no ports and cost the same on the Go side (same
  `net.Conn`, `bufio.Reader`, relay buffers, goroutines). The exception is
  `socksudp`, which must use TCP: `ASSOCIATE` derives its `BND.ADDR` from the
  control conn's `*net.TCPAddr` and its egress is real UDP.
- **The associate ramp holds associations fixed (200) and ramps flows**, so the
  slope is the per-flow cost directly — which is the number that decides capacity,
  since one client can hold `AssociateMaxFlows` of them.

### To re-measure a knob

Change the constant and re-run; the harness reports the new marginal cost.

```sh
# e.g. what would 32KiB relay buffers cost?
#   internal/relay/relay.go: BufferSize = 32768   (note: >4KiB is NOT pooled by
#   connect's message pool, so this also adds GC churn)
PROXY_CAPACITY=1 go test -v -run TestCapacitySocksConnect ./
```

---

## 4. What these numbers do NOT include

Be honest about the edges before trusting the ceiling:

- **Kernel socket buffers are not in RSS** — but a cgroup memory limit *does*
  charge them (`memory.stat` `sock`). At 2 sockets per client this is real memory
  the 8GiB cap sees and this measurement does not.
- **The production upstream is a gVisor endpoint, and under load it dominates.**
  Every tunnel's upstream leg and every associate flow is a gVisor endpoint living
  *inside* the proxy process, with Go-heap buffers sized by `connect/tun.go`. This
  harness dials a kernel socket instead, so none of that is in the numbers above.
  It has now been measured directly (`connect/tun_capacity_test.go`, which loops a
  dial back inside the tun's own stack via `HandleLocal`):

  | gVisor endpoint | idle | **backlogged** | |
  |---|---|---|---|
  | TCP (per endpoint) | 6.7 KiB | **183.8 KiB** | 28x |
  | UDP (per flow) | 3.5 KiB | **576.3 KiB** | 167x |

  gVisor buffer sizes are LIMITS on what may be queued, not preallocations — hence
  the enormous idle/loaded gap. **An idle tunnel is cheap and a backlogged one is
  not**, and the numbers in §1 are all idle. A backlogged CONNECT tunnel costs
  ~184 KiB (gVisor) + ~25 KiB (proxy) ≈ **210 KiB**, i.e. **~40,000 backlogged
  tunnels per 8GiB** against ~330,000 idle ones. Real capacity sits between,
  depending on what fraction of tunnels are backlogged at once.

- **These are idle tunnels.** They are the steady state for a proxy (most
  connections are idle at any instant), but they are a *ceiling*, not a promise
  under load.
