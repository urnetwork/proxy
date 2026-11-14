# SOCKS5 Cleanroom Plan

Status: implemented (package `proxy/socks5`)
Owner: proxy
Scope: replace the `github.com/things-go/go-socks5` dependency with a small,
first-principles SOCKS5 server we control, and in doing so fix the leaks and the
tunnel-bypass in the UDP `ASSOCIATE` path.

## As-built notes (deviations from the plan below)

The implementation follows this plan with a few deliberate refinements:

- **No per-association sweeper goroutine.** Idle reclamation is driven purely by
  a per-flow read deadline anchored to the *last client activity* (not last
  inbound), so a flow the client abandoned is reclaimed even if the destination
  keeps sending. This is strictly tighter at scale than the planned sweeper — no
  ticker and no extra goroutine per association.
- **Cap eviction is strict LRU** rather than "evict-oldest-idle-or-drop": at
  capacity the least-recently-used flow is evicted so a new flow is always
  admitted, guaranteeing the table never exceeds `AssociateMaxFlows`.
- **UDP datagram buffer is a fixed 65535** (+header prefix) rather than a knob —
  the RFC max, so datagrams are never truncated. Memory is bounded by the flow
  cap; tune `AssociateMaxFlows` for memory.
- **`Resolve` hook dropped.** FQDNs are preserved to the dialer by default
  (the tunnel resolves via DoH), matching what the server consumer already relies
  on.
- **Added `HandshakeTimeout`** (default 30s): negotiation + request parsing are
  deadline-bounded so a half-open client cannot pin a goroutine.
- **Each UDP datagram is dialed with its own synthesized `Request`** whose
  `DestAddr` is that datagram's destination, so the caller's per-destination FQDN
  handling works for UDP exactly as for CONNECT.
- **Dial-error → reply-code mapping** lives in `socks5.ReplyCodeForDialError`
  (the CONNECT handler that needs it moved into the package).

Files: `socks5/{socks5,addr,message,datagram,relay,server,associate}.go`;
tests: `socks5/{codec,server,leak,associate_regress}_test.go` (unit + fuzz +
integration + leak + scale, all passing under `-race`). `SocksProxy` in
`socks.go` is now a thin adapter; the CLI (`socks/main.go`) uses `socks5.Server`
directly with glog.

## Post-review fixes

A multi-agent review of the implementation (plus the http and wg proxies) found
several defects, since fixed. Three are worth carrying forward as design notes:

- **Cancellation must close, not just poke deadlines.** The relay originally tore
  down by setting a read deadline in the past. That cannot interrupt a goroutine
  blocked in `Write`, is erased by the copy loop's next deadline re-arm, and is a
  no-op on an endpoint with no deadline support at all (net/http's 101-upgrade
  body). The result was a circular wait: the caller's `defer conn.Close()` — the
  only thing that could unblock the parked goroutine — ran only *after* the relay
  returned. Cancellation now poisons deadlines **and** closes every endpoint. This
  logic lives in ONE place, `internal/relay`, shared by the socks and http
  proxies, precisely so it cannot drift again.
- **The idle timer is refreshed by traffic in BOTH directions.** Anchoring it to
  outbound only (RFC 4787 REQ-6 permits this) reclaimed a flow that was actively
  *receiving* — a client that sends one request and then only listens. Because a
  re-created flow dials from a new egress port, the sender keeps talking to a dead
  port, so the stream breaks permanently rather than pausing. Refreshing on inbound
  is safe here: the association dies with its control connection and the flow count
  is capped, so nothing can be extended without bound.
- **Dial before evicting.** `openFlow` made room *before* dialing, so a
  destination that could not be dialed still cost a healthy live flow. At capacity,
  a client retrying an undialable destination would progressively tear down its own
  working mappings.

Each fix has a regression test that has been confirmed to fail against the old
behavior.

## Capacity: concurrent clients per 8GiB process

Measured by `capacity_test.go`, which runs each proxy in a CHILD process (so the
test's own client and backend memory is not folded into the number), ramps to
30k concurrent idle tunnels, and fits the MARGINAL cost per client. Run it with
`PROXY_CAPACITY=1 go test -run TestCapacity -v ./` — never under `-race`.

| proxy | per client | clients per 8GiB |
|-------|-----------|------------------|
| socks CONNECT | 25.3 KiB | **~330,000** |
| http CONNECT | 33.4 KiB | **~250,000** |
| wireguard (registered peer) | 23.7 KiB | ~353,000, but the device caps at `MaxPeers` = 65,536 |

Two findings drove this, and both are worth preserving:

- **The relay buffer is multiplied by every concurrent connection.** A buffer is
  held for the whole lifetime of a relay direction, not just while bytes move. At
  the 32kib `io.Copy` default a tunnel costs 64kib; at 2kib it costs 4kib. That
  one constant (`relay.BufferSize`) is worth ~3x of the capacity above.
- **Goroutine stacks were the single largest per-connection item** — larger than
  the buffers. Each tunnel used to carry 4 (socks) or 5 (http) goroutines. Two
  were removable: the cancellation watcher became a `context.AfterFunc` (which
  holds NO goroutine while it waits), and one copy direction now runs on the
  caller's goroutine instead of spawning a second. Both proxies now carry 2
  goroutines per client, which bought +29% (socks) and +35% (http).

Caveats on the numbers: RSS excludes kernel socket buffers, which a cgroup does
charge. And in production the upstream leg is a gVisor endpoint inside the same
process (its buffers are Go heap, sized by `connect`'s tun settings), not the
kernel socket the harness uses — so a busy tunnel costs more than an idle one
measured here. Treat these as the ceiling for idle-tunnel capacity, not a
promise under load. For wireguard, an ACTIVE client additionally carries a tun
(a gVisor netstack owned by `connect`), which dwarfs the 23.7 KiB peer record.

---

## 1. Motivation

`socks.go` builds a `things-go/go-socks5` server that permits `CONNECT` **and**
`ASSOCIATE` (`socks5.NewPermitConnAndAss()`), overrides `CONNECT` with our own
handler (`WithConnectHandle`), but provides **no** associate handler. So every
UDP `ASSOCIATE` runs the upstream default `handleAssociate`
(`go-socks5@v0.1.1/handle.go:181`), which we inherit unchanged and which is
untested here (`socks_test.go` covers only `CONNECT`).

That default handler has two critical problems and three lesser ones. The two
critical ones cannot be fixed with a small patch at the call site — they are
structural — which is why we are rebuilding rather than wrapping.

### 1.1 Defects in the inherited associate path

The upstream handler spawns one **relay** goroutine that reads client datagrams
from a UDP socket (`bindLn`) and owns a `conns sync.Map` of per-destination
target sockets; for each new destination it spawns one **reader** goroutine that
reads replies and writes them back to the client. The original goroutine then
blocks reading the TCP control connection to keep the association alive.

| # | Defect | Upstream location | Severity | Effect |
|---|--------|-------------------|----------|--------|
| 1 | No idle timeout and no cap: every distinct `(srcAddr,dstAddr)` permanently holds a reader goroutine + target UDP socket + 32 KB buffer, reclaimed only on a target read error or full teardown. UDP has no EOF and no read deadline is ever set, so quiet destinations (DNS, QUIC, STUN, one-shot req/resp) leak until the client drops TCP. | `handle.go:263‑306`, `:274` | **Critical** | Unbounded goroutine / fd / memory growth per association |
| 2 | Associate dials with `sf.dial` (set by `WithDial`), but we only set `WithDialAndRequest` (`sf.dialWithRequest`). `sf.dial` is nil → falls back to raw `net.Dial`. UDP associate traffic **egresses from the host OS stack, outside the urnetwork tunnel**, and ignores `ctx`. | `handle.go:183‑188` | **Critical** | Traffic leaves the tunnel; correctness/privacy break |
| 3 | A single target send/read error `return`s the relay goroutine, whose defer closes `bindLn` and every other target — one transient failure kills all of a client's unrelated flows. | `handle.go:303‑316` | High | Spurious drops of unrelated flows |
| 4 | When the relay dies (defect 3), it closes `bindLn`, but that does not unblock the control-conn read loop (which reads the TCP conn, not `bindLn`). The control goroutine + its 32 KB buffer are stranded until the client independently closes TCP. | `handle.go:321‑334` | Medium | Leaked goroutine/buffer until client drops TCP |
| 5 | The reply header for **IPv6** destinations is built from `pk.DstAddr.IP`, which aliases the relay's single read buffer (`datagram.go:64`); the reader goroutine reads it (`handle.go:293`) concurrently with the relay overwriting the buffer on the next `ReadFromUDP`. Data race + corrupted reply address. | `handle.go:250‑293` | Medium | Race (visible under `-race`) + corrupted DST.ADDR in replies |

The through-line: the upstream default was written for a simple embedded relay,
not a high-concurrency privacy proxy. It has no NAT-table lifecycle (TTL, caps,
per-flow isolation), no deadline discipline, and no integration with our tunnel
dialer.

### 1.2 What we already own and trust

The `CONNECT` data path is ours and is solid: `connectHandle` (`socks.go:98`)
plus `copyRw` / `copyBufferWithTimeout` (`util.go`) are tunnel-aware and
deadline-disciplined. We keep them.

---

## 2. Goals / non-goals

**Goals**
- A minimal SOCKS5 server implemented from RFC 1928 / RFC 1929 that covers
  exactly what we use: method negotiation (no-auth + username/password),
  `CONNECT`, and UDP `ASSOCIATE`.
- All egress — TCP and UDP — routed through the existing
  `ConnectDialWithRequest`, so associate traffic goes through the tunnel.
- A UDP associate relay with a bounded, TTL-evicted NAT table; per-flow error
  isolation; correct teardown tied to the TCP control connection; and no data
  races.
- Drop the `github.com/things-go/go-socks5` dependency entirely.
- `CONNECT` behavior stays byte-for-byte identical; existing `socks_test.go`
  passes unchanged.

**Non-goals**
- `BIND` (already unsupported; continue to reply "command not supported").
- GSSAPI auth.
- UDP fragment reassembly (`FRAG != 0`): we reject/drop, as is standard for
  relays that do not implement it.
- A general-purpose reusable SOCKS library. This is scoped to our needs.

---

## 3. Settled design decisions

- **`BND.ADDR` for the associate reply = the control connection's local IP**,
  with the relay UDP port. This mirrors current behavior
  (`udpAddr = {IP: tcpAddr.IP, Port: 0}`; reply with the relay socket's
  `LocalAddr()`). In the new handler the underlying `net.Conn` is in scope, so
  we take `conn.LocalAddr().(*net.TCPAddr).IP` and the relay socket's port.
- **Full replacement** of `things-go/go-socks5`, not a `WithAssociateHandle`
  shim. The remaining upstream surface we use (negotiation, request parse, reply
  encode, associate) is small and is exactly where the bugs and the dependency
  live. This matches the "correct and minimal, from first principles" intent.
- **Egress dialer** is the existing `ConnectDialWithRequest(ctx, r, network,
  addr)`; associate calls it with `network == "udp"`. The tunnel dialer already
  supports UDP (`connect/tun.go:721‑733`, returns a `*gonet.UDPConn`).
- **Buffers**: a dedicated `sync.Pool` of max-datagram-sized buffers for the UDP
  relay (see §7), **not** `connect.MessagePool` (which only pools ≤ 4096 B and
  would silently truncate larger UDP datagrams).

---

## 4. Package layout

New internal package; `SocksProxy` in `socks.go` becomes a thin adapter.

```
proxy/socks5/
  addr.go        # ATYP <-> address encode/decode (v4 / v6 / domain). No aliasing
                 # of caller buffers into returned addresses.
  message.go     # method-select negotiation, username/password auth, request and
                 # reply structs + encode/decode over io.Reader / io.Writer.
  datagram.go    # UDP request header encode/decode; FRAG==0 enforcement.
  server.go      # Server struct + options (Dial, ValidUser, Resolve, timeouts,
                 # associate limits).
  conn.go        # per-connection lifecycle: handshake -> auth -> parse -> dispatch.
  connect.go     # CONNECT handler (port of connectHandle; reuse copyRw).
  associate.go   # UDP ASSOCIATE handler: relay + NAT table + idle sweeper.
```

`socks.go` keeps the public `SocksProxy` type and its fields
(`ConnectDialWithRequest`, `ValidUser`, `Log`, `ProxyReadTimeout`,
`ProxyWriteTimeout`) and gains associate settings (§6). Its `ListenAndServe`
constructs a `socks5.Server` instead of a `go-socks5` server.

---

## 5. Wire-format components (`addr.go`, `message.go`, `datagram.go`)

Small, pure, fuzzable. All decoders take an `io.Reader` (stream) or `[]byte`
(datagram) and **copy** any bytes they retain — no returned value aliases an
input buffer (this is the class of bug behind defect 5).

**`addr.go`** — encode/decode of `ATYP + ADDR + PORT`:
- `ATYP` 0x01 IPv4, 0x03 domain, 0x04 IPv6.
- `type Addr struct { IP net.IP; FQDN string; Port int }` with
  `AppendTo([]byte) []byte`, `WireLen() int`, and a stream decoder
  `ReadAddr(io.Reader) (Addr, error)`.
- Domain names are decoded with `string(...)` (copy); IPv6 is decoded into a
  freshly allocated 16-byte slice (never aliases the source).

**`message.go`** — the TCP handshake and request/reply:
- `ReadMethods(io.Reader) ([]byte, error)` / write the selected method.
- Username/password auth (RFC 1929): `ReadUserPass(io.Reader) (user, pass
  string, err error)`, then a 1-byte status reply.
- `type Request struct { Cmd byte; Dst Addr }`, `ReadRequest(io.Reader)`.
- `type Reply struct { Rep byte; Bnd Addr }`, `(Reply).AppendTo` /
  `WriteReply(io.Writer, rep byte, bnd net.Addr)`. `bnd` accepts
  `*net.TCPAddr` / `*net.UDPAddr` and encodes v4/v6 accordingly.
- Reply codes reused from our existing `mapDialErrorToSocksReply` mapping in
  `socks.go` (keep that function; it already handles gVisor/gonet error
  strings).

**`datagram.go`** — the UDP relay header (RFC 1928 §7):
`RSV(2) FRAG(1) ATYP ADDR PORT DATA`.
- `ParseDatagram(b []byte) (frag byte, dst Addr, payload []byte, err error)`.
  `payload` is a subslice of `b` (caller owns `b` for the read's lifetime and
  must not retain `payload` past it).
- `AppendDatagramHeader(dst []byte, a Addr) []byte` for building replies.
- Enforce `frag == 0`; drop otherwise (we do not reassemble).

---

## 6. Server and options (`server.go`)

```go
type Server struct {
    Dial      func(ctx context.Context, r *Request, network, addr string) (net.Conn, error)
    ValidUser func(user, pass, userAddr string) bool // nil => no-auth allowed
    Resolve   func(ctx context.Context, name string) (net.IP, error) // nil => preserve FQDN
    Log       connect.Logger

    ReadTimeout  time.Duration
    WriteTimeout time.Duration

    // associate
    AssociateIdleTimeout time.Duration // per-flow idle TTL; default 60s
    AssociateMaxFlows    int           // per-association NAT-table cap; default 512
}
```

Notes:
- `Dial` unifies TCP and UDP egress; the request is threaded through so the dial
  callback can see the SOCKS request (matches current `ConnectDialWithRequest`).
- `Resolve` returning nil IP preserves the FQDN for the dialer, exactly as the
  current `SocksProxy.Resolve` does.
- Defaults chosen (tunable): idle TTL 60 s, max flows 512, sweeper interval
  `AssociateIdleTimeout/2`.

---

## 7. UDP ASSOCIATE design (`associate.go`)

This is the crux — it fixes defects 1–5.

### 7.1 Association lifecycle

On an `ASSOCIATE` request, on the goroutine handling the TCP control connection:

1. Open the relay UDP socket bound to the control-conn local IP:
   `relay, _ := net.ListenUDP("udp", &net.UDPAddr{IP: controlLocalIP, Port: 0})`.
2. Reply `RepSuccess` with `BND.ADDR = {controlLocalIP, relay.LocalAddr().Port}`
   (settled decision §3).
3. Create `assocCtx, cancel := context.WithCancel(serverCtx)`.
4. Spawn the **relay goroutine** (client → target).
5. Start the **idle sweeper** (a `time.Ticker`).
6. Block reading the TCP control connection. When that read returns (client
   closed, or error) **or** `serverCtx` is done, call `cancel()` and close
   `relay`.

`cancel()` + `relay.Close()` is the single teardown trigger. It unblocks the
relay goroutine; the relay's defer closes every NAT entry (each entry's target
socket close unblocks its reader goroutine); the sweeper stops. Unlike upstream,
teardown propagates in both directions — a dead relay also cancels the control
side (fixes defect 4).

### 7.2 NAT table

```go
type flow struct {
    conn       net.Conn   // tunnel UDP conn from Dial(ctx, r, "udp", dst)
    dst        Addr       // stable copy for building reply headers (fixes defect 5)
    lastActive atomic.Int64 // unixnano; touched on client->target activity
}

type natTable struct {
    mu      sync.Mutex
    flows   map[string]*flow // key: dst.String()
    max     int
}
```

- Key by destination address string (the association already pins one client —
  see 7.3). `sync.Mutex` + explicit map; no `sync.Map` (we need sweep + cap
  logic).
- **Cap** at `AssociateMaxFlows`. On insert when full, evict the oldest-idle
  flow; if none is idle, drop the new datagram (never kill the association).
- **Idle TTL** via two mechanisms working together:
  - each target `conn` carries `SetReadDeadline(now + idleTTL)`, refreshed on
    client→target activity, so an idle flow's reader goroutine wakes on the
    deadline and exits instead of blocking forever (the tunnel `*gonet.UDPConn`
    supports deadlines — verified);
  - the sweeper periodically closes+removes flows whose `lastActive` is older
    than the TTL (belt and suspenders, and covers flows with steady inbound but
    no outbound).

### 7.3 Relay goroutine (client → target)

Loop over `relay.ReadFromUDP(buf)`:

1. On first datagram, **pin** the client's UDP source address (the datagram's
   `srcAddr`), subject to the request's `DstAddr` filter as today; ignore
   datagrams from other sources.
2. `ParseDatagram`; enforce `frag == 0` (drop otherwise).
3. Look up `flows[dst]`. If present, write `payload` to `flow.conn`, touch
   `lastActive`, refresh its read deadline. A write error removes **only that
   flow** (fixes defect 3).
4. If absent and under cap: `conn, err := s.Dial(assocCtx, req, "udp",
   dst.String())` — **through the tunnel** (fixes defect 2). Store the flow with
   a stable copy of `dst`, spawn its reader goroutine, write the payload.
5. If absent and at cap: evict oldest-idle or drop.

`buf` is a max-datagram buffer from the relay's dedicated pool; nothing derived
from it is retained past the iteration.

### 7.4 Reader goroutine (target → client), one per flow

Loop:

1. `flow.conn.SetReadDeadline(now + idleTTL)`.
2. `n, err := flow.conn.Read(rbuf)`.
3. On data: build reply into a pooled buffer =
   `AppendDatagramHeader(nil-header-from flow.dst)` + `rbuf[:n]`, then
   `relay.WriteTo(reply, pinnedClientAddr)`. The header is built from
   `flow.dst` (a stable copy captured at dial time), never from the relay's
   shared read buffer — **fixes defect 5**.
4. On timeout: if `lastActive` older than TTL, remove flow + close + return;
   else continue.
5. On any other error / closed: remove flow + close + return (this flow only).

### 7.5 Buffers

UDP datagrams can be up to 65 507 B of payload; a read buffer smaller than the
datagram silently drops the tail (UDP semantics), so the relay read buffer and
the reply buffer must be full-size. `connect.MessagePool` only pools 2048/4096-B
buffers, so it is unsuitable here (larger requests allocate-and-drop and would
truncate). Use a package-local pool:

```go
const maxDatagram = 65535
var udpBufPool = sync.Pool{New: func() any { b := make([]byte, maxDatagram); return &b }}
```

Reply buffer is sized `headerLen + payloadLen` (header ≤ 262 B for a domain);
size the pooled reply buffer at `maxDatagram + 262` or assemble in a second
pooled buffer.

---

## 8. Concurrency & teardown model (goroutine ownership)

Per association:
- 1 control goroutine (blocks on the TCP control read; owns teardown).
- 1 relay goroutine (owns `relay` reads and the NAT table writes).
- 1 sweeper goroutine (ticker).
- N reader goroutines, one per live flow, bounded by `AssociateMaxFlows`.

Invariants:
- The only teardown trigger is `cancel()` + `relay.Close()` from the control
  goroutine (on TCP read return or `serverCtx` done).
- A per-flow error never tears down more than that flow.
- After teardown, goroutine and socket counts return to baseline. This is
  asserted by a leak test (§10) in the style of `wg_perf_count_norace_test.go`.

---

## 9. Integration with `SocksProxy` (`socks.go`)

- `SocksProxy` keeps its fields and gains `AssociateIdleTimeout` and
  `AssociateMaxFlows`.
- `ListenAndServe` builds a `socks5.Server` with:
  - `Dial:` the existing `ConnectDialWithRequest` (now also called with
    `"udp"`),
  - `ValidUser:` the existing callback,
  - `Resolve:` the existing FQDN-preserving resolver,
  - timeouts and associate limits.
- The per-conn accept loop stays; `socksServer.ServeConn(conn)` becomes
  `server.ServeConn(ctx, conn)`.
- Keep `mapDialErrorToSocksReply` and the `copyRw`/`copyBufferWithTimeout`
  helpers; `connect.go` reuses them so the `CONNECT` path is unchanged.

### 9.1 External prerequisite (cross-repo)

The `ConnectDialWithRequest` **callback is supplied by the caller** of this
library and today is only ever invoked with `network == "tcp"`. For associate to
egress through the tunnel, that callback must handle `network == "udp"` and route
to `tun.DialContext(ctx, "udp", addr)` (which returns a `*gonet.UDPConn`). This
is the one change required outside this repo and is a prerequisite for the
associate egress to work. Until it is in place, associate should remain disabled
(see §11 rollout).

---

## 10. Testing plan

**Codec unit + fuzz** (`addr`, `message`, `datagram`):
- Round-trip encode/decode for v4/v6/domain addresses and requests/replies.
- Fuzz malformed inputs: short buffers, bad `ATYP`, domain-length overflow,
  truncated ports. (Upstream had several `len(b) <= headLen` edge cases worth
  pinning.)

**Associate integration**:
- A UDP echo backend reached via a fake `Dial` that returns an in-memory or
  loopback UDP conn; drive a real SOCKS5 UDP associate client (build minimal
  datagram framing in the test).
- Assert: correct header + payload round-trip; several simultaneous
  destinations; FRAG!=0 dropped; source-pinning (datagram from wrong src
  ignored).
- Idle eviction: a flow goes quiet past the TTL → its goroutine and socket are
  gone (poll goroutine count / a close hook).
- Cap enforcement: exceed `AssociateMaxFlows` → oldest-idle evicted, association
  survives, no unbounded growth.

**Leak / teardown** (mirror `wg_perf_count_norace_test.go`):
- N associations × M destinations, then close; assert goroutine and fd counts
  return to baseline.
- Kill the TCP control conn mid-flight; assert every UDP socket and goroutine is
  reclaimed.
- Run the whole suite under `-race` to keep defect 5 from regressing.

**CONNECT regression**: existing `socks_test.go` passes unchanged.

---

## 11. Rollout / sequencing

1. Land `proxy/socks5` with negotiation / auth / request / reply + the `CONNECT`
   handler (port of `connectHandle`, reuse `copyRw`). Wire `SocksProxy` to it.
   Confirm `socks_test.go` passes. Pure refactor, no behavior change.
2. Add the associate handler + NAT table + sweeper + settings.
3. Add associate integration + leak tests; run under `-race`.
4. Land the cross-repo `ConnectDialWithRequest` `"udp"` wiring (§9.1).
5. Remove `github.com/things-go/go-socks5` from `go.mod`; delete the last import.
   Update or retire `socks/main.go` (the CLI still imports go-socks5 directly and
   dials `dev.DialContext(ctx,"tcp",addr)`; point it at the new server or drop
   it — it is a dev tool, not on the server path).

Optionally gate associate behind a flag until step 4 is deployed, so we do not
advertise a UDP relay that cannot reach the tunnel.

---

## 12. What we delete

- Dependency `github.com/things-go/go-socks5` (server, `handle.go`,
  `ruleset.go`, `bufferpool`, `statute`) — all of it.
- Reliance on the upstream 32 KB `bufferpool` for the relay path (replaced by the
  dedicated max-datagram pool).

We keep: `copyRw`, `copyConn`, `copyBufferWithTimeout(AndFlush)` (`util.go`);
`mapDialErrorToSocksReply` and the `SocksProxy` public surface (`socks.go`).

---

## 13. Defaults chosen (tune if needed)

| Setting | Default | Rationale |
|---------|---------|-----------|
| `AssociateIdleTimeout` | 60 s | Covers DNS/QUIC idle gaps without holding flows long |
| `AssociateMaxFlows` | 512 per association | Bounds fd/goroutine use; generous for real clients |
| Sweeper interval | TTL/2 (30 s) | Bounded lag on idle reclamation |
| `maxDatagram` | 65535 | UDP max; avoids truncation |
| FRAG != 0 | drop | We do not reassemble |
| Overflow policy | evict oldest-idle, else drop datagram | Never kill the association |
| Source policy | pin client src on first datagram (+ request DstAddr filter) | Standard relay behavior |
| Auth | no-auth + username/password via `ValidUser` | Preserves current behavior |
