package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The associate relay carries datagrams up to SocksProxySettings.MaxDatagramSize (4kib by
// default) and DROPS anything larger. It never truncates.
//
// That distinction is the whole reason this code is shaped the way it is. A UDP
// read into a buffer smaller than the datagram silently discards the tail: it
// returns n == len(buf) with a nil error, and there is no way after the fact to
// tell a datagram that exactly filled the buffer from one that overflowed it. So
// a relay that simply sizes its buffer to the limit will forward truncated —
// that is, corrupted — payloads, with nothing anywhere reporting a problem.
//
// The fix is to read into ONE MORE BYTE than the largest datagram we accept. A
// read that fills that buffer is therefore known to be oversize (it is either
// exactly limit+1, or it was truncated from something larger — either way it
// exceeds the limit) and is dropped. A read that does not fill it is known to be
// complete.
//
// A payload-length check is needed on top of the buffer check, not instead of
// it: the encapsulated form is header+payload, and the header varies from 10 to
// 262 bytes, so a datagram with a small header can carry an oversize payload and
// still fit inside the buffer.

// socksMaxUdpReadLen is the read buffer size that makes an oversize datagram
// detectable: the largest form we accept, plus the sentinel byte.
func socksMaxUdpReadLen(maxDatagramSize int) int {
	return maxDatagramHeaderLen + maxDatagramSize + 1
}

var udpBufPools sync.Map // maxDatagramSize -> *sync.Pool

// udpBufPool returns the buffer pool for a datagram limit. SocksProxySettings are fixed
// for a server's lifetime, so in practice this is a single pool.
func udpBufPool(maxDatagramSize int) *sync.Pool {
	if pool, ok := udpBufPools.Load(maxDatagramSize); ok {
		return pool.(*sync.Pool)
	}
	size := socksMaxUdpReadLen(maxDatagramSize)
	pool, _ := udpBufPools.LoadOrStore(maxDatagramSize, &sync.Pool{
		New: func() any {
			b := make([]byte, size)
			return &b
		},
	})
	return pool.(*sync.Pool)
}

// udpFlow is one client<->destination UDP mapping in an association.
type udpFlow struct {
	key    string
	dst    *AddrSpec    // stable copy; used to build reply headers
	conn   net.Conn     // egress conn to the destination (through Dial)
	client *net.UDPAddr // where replies are sent

	last      atomic.Int64 // last client->target activity, unix nanos
	closeOnce sync.Once
}

func (f *udpFlow) touch()            { f.last.Store(time.Now().UnixNano()) }
func (f *udpFlow) lastActive() int64 { return f.last.Load() }
func (f *udpFlow) close()            { f.closeOnce.Do(func() { f.conn.Close() }) }

// association is the state for one UDP ASSOCIATE, owned by the control
// connection's goroutine. One relay goroutine reads client datagrams; one
// reader goroutine per flow reads destination replies. All are tracked by wg so
// teardown is deterministic.
type association struct {
	server *socksServer
	req    *Request     // the ASSOCIATE request (carries AuthContext etc.)
	relay  *net.UDPConn // client-facing socket
	ctx    context.Context

	idle            time.Duration
	maxFlows        int
	writeTimeout    time.Duration
	maxDatagramSize int
	stats           *SocksStats

	// expected client source from the ASSOCIATE request (may be unset).
	expectIP   net.IP
	expectPort int

	mu     sync.Mutex
	client *net.UDPAddr // pinned client source (first accepted datagram)
	flows  map[string]*udpFlow

	wg sync.WaitGroup
}

// handleAssociate sets up the relay, replies with the bind address (the control
// connection's local IP + relay port), and holds the association open until the
// control connection closes or ctx is canceled — then tears everything down and
// waits for every goroutine and socket to be released before returning.
func (s *socksServer) handleAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	localIP := net.IP(net.IPv4zero)
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok && tcpAddr.IP != nil {
		localIP = tcpAddr.IP
	}

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		writeReply(conn, repServerFailure, nil)
		return err
	}

	bnd := &net.UDPAddr{IP: localIP, Port: relay.LocalAddr().(*net.UDPAddr).Port}
	conn.SetDeadline(time.Time{})
	if err := writeReply(conn, repSuccess, bnd); err != nil {
		relay.Close()
		return err
	}

	assocCtx, cancel := context.WithCancel(ctx)

	settings := s.settings
	a := &association{
		server:          s,
		req:             req,
		relay:           relay,
		ctx:             assocCtx,
		idle:            settings.AssociateIdleTimeout,
		maxFlows:        settings.AssociateMaxFlows,
		writeTimeout:    settings.ProxyWriteTimeout,
		maxDatagramSize: settings.MaxDatagramSize,
		stats:           &s.stats,
		flows:           make(map[string]*udpFlow),
	}
	if req.DestAddr != nil {
		a.expectIP = req.DestAddr.IP
		a.expectPort = req.DestAddr.Port
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.runClientToTarget()
	}()

	// Unblock the control read when the association context is canceled
	// (e.g. server shutdown) so teardown does not wait on client behavior.
	stop := context.AfterFunc(assocCtx, func() {
		conn.SetReadDeadline(time.Now())
	})

	// Teardown: stop the watcher, cancel egress, close the relay (unblocks the
	// relay goroutine, whose defer closes every flow), then wait for all
	// goroutines and sockets to be released.
	defer func() {
		stop()
		cancel()
		relay.Close()
		a.wg.Wait()
	}()

	// Hold the association open for the life of the TCP control connection.
	var ctrl [512]byte
	for {
		if _, err := conn.Read(ctrl[:]); err != nil {
			return nil
		}
	}
}

// runClientToTarget reads client datagrams and forwards them to destinations.
// On exit it closes every flow, which unblocks the per-flow readers.
func (a *association) runClientToTarget() {
	defer a.closeAllFlows()

	pool := udpBufPool(a.maxDatagramSize)
	bp := pool.Get().(*[]byte)
	defer pool.Put(bp)
	buf := *bp

	for {
		n, src, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == len(buf) {
			// the read filled the sentinel byte, so this datagram is oversize (or
			// was truncated from something larger). Forwarding it would corrupt the
			// payload silently; drop it instead.
			a.stats.AssociateOversizeDatagrams.Add(1)
			continue
		}
		a.forwardClientDatagram(buf[:n], src)
	}
}

// forwardClientDatagram validates the source, parses the datagram, and writes
// the payload to the destination flow (creating it if needed).
func (a *association) forwardClientDatagram(dgram []byte, src *net.UDPAddr) {
	if !a.acceptSource(src) {
		a.stats.AssociateForeignDatagrams.Add(1)
		return
	}
	frag, dst, payload, err := parseDatagram(dgram)
	if err != nil || frag != 0 {
		// malformed or fragmented (we do not reassemble): drop.
		a.stats.AssociateMalformedDatagrams.Add(1)
		return
	}
	if a.maxDatagramSize < len(payload) {
		// the buffer check above cannot catch this on its own: the header is 10 to
		// 262 bytes, so a small header can carry an oversize payload and still fit.
		a.stats.AssociateOversizeDatagrams.Add(1)
		return
	}
	key := dst.String()

	a.mu.Lock()
	f := a.flows[key]
	a.mu.Unlock()

	if f == nil {
		f = a.openFlow(key, dst, src)
		if f == nil {
			return
		}
	}

	f.touch()
	if 0 < a.writeTimeout {
		f.conn.SetWriteDeadline(time.Now().Add(a.writeTimeout))
	}
	if _, err := f.conn.Write(payload); err != nil {
		// A single destination failing must never affect other flows.
		if errors.Is(err, net.ErrClosed) {
			a.removeFlow(f)
			return
		}
		// A transient egress error (an ICMP-driven ECONNREFUSED on a connected
		// UDP socket, a full send buffer) must not destroy the mapping either:
		// re-dialing would take a new egress port and break the destination's
		// view of the flow. Drop this datagram and keep the flow.
		a.stats.AssociateSendErrors.Add(1)
	}
}

// openFlow dials a destination and registers a new flow, evicting the
// least-recently-used flow if the association is at capacity. It runs only on
// the single relay goroutine, so there is no concurrent creation to race.
//
// The dial happens BEFORE any eviction: a failed dial must not cost a live flow.
// Evicting first would let a client that keeps retrying an undialable
// destination progressively tear down its own healthy mappings.
func (a *association) openFlow(key string, dst *AddrSpec, client *net.UDPAddr) *udpFlow {
	// Dial outside the lock (it may block); the flow's own request carries the
	// per-datagram destination so the caller's FQDN handling works per flow.
	freq := &Request{
		Command:     cmdAssociate,
		DestAddr:    dst,
		RawDestAddr: dst,
		AuthContext: a.req.AuthContext,
		LocalAddr:   a.req.LocalAddr,
		RemoteAddr:  a.req.RemoteAddr,
	}
	conn, err := a.server.Dial(a.ctx, freq, "udp", key)
	if err != nil {
		a.stats.AssociateDialErrors.Add(1)
		return nil
	}

	f := &udpFlow{
		key:    key,
		dst:    dst.clone(),
		conn:   conn,
		client: &net.UDPAddr{IP: append(net.IP(nil), client.IP...), Port: client.Port, Zone: client.Zone},
	}
	f.touch()

	a.mu.Lock()
	if a.ctx.Err() != nil {
		a.mu.Unlock()
		conn.Close()
		return nil
	}
	// make room only now that there is a replacement to admit
	var evicted *udpFlow
	if a.maxFlows <= len(a.flows) {
		evicted = a.evictLRULocked()
	}
	a.flows[key] = f
	a.wg.Add(1)
	a.mu.Unlock()
	a.stats.AssociateFlowsOpened.Add(1)

	if evicted != nil {
		a.stats.AssociateFlowsEvicted.Add(1)
		evicted.close()
	}

	go func() {
		defer a.wg.Done()
		a.runTargetToClient(f)
	}()
	return f
}

// runTargetToClient reads destination replies and writes them back to the
// client, prefixed with the SOCKS UDP header. It reclaims the flow when it has
// been idle in BOTH directions for a full TTL (via a read deadline anchored to
// the last activity) or when the egress conn dies.
func (a *association) runTargetToClient(f *udpFlow) {
	defer a.removeFlow(f)

	pool := udpBufPool(a.maxDatagramSize)
	bp := pool.Get().(*[]byte)
	defer pool.Put(bp)
	buf := *bp
	// replies are read after a header-sized prefix, so the SOCKS header can be
	// written in front of the payload without copying it. The read window is the
	// payload limit plus the sentinel byte.
	readBuf := buf[maxDatagramHeaderLen:]

	for {
		deadline := time.Unix(0, f.lastActive()).Add(a.idle)
		if err := f.conn.SetReadDeadline(deadline); err != nil {
			return
		}
		n, err := f.conn.Read(readBuf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if a.idle <= time.Since(time.Unix(0, f.lastActive())) {
					return // idle in both directions for a full TTL: reclaim.
				}
				continue // activity refreshed the deadline; re-anchor.
			}
			return
		}

		// Inbound traffic keeps the flow alive too. Anchoring the idle timer to
		// outbound activity alone would reclaim a flow that is actively receiving
		// (a client that sends one request and then only listens), and the
		// re-created flow would dial from a new egress port, permanently breaking
		// the stream rather than merely pausing it. Refreshing on inbound cannot
		// extend anything without bound: the association dies with its control
		// connection, and the flow count is capped by maxFlows.
		if n == len(readBuf) {
			// oversize (or truncated from something larger): drop rather than relay a
			// corrupted payload to the client. See the note at the top of this file.
			a.stats.AssociateOversizeReplies.Add(1)
			f.touch()
			continue
		}

		f.touch()

		hl := datagramHeaderLen(f.dst)
		hstart := maxDatagramHeaderLen - hl
		appendDatagramHeader(buf[hstart:hstart:maxDatagramHeaderLen], f.dst)
		out := buf[hstart : maxDatagramHeaderLen+n]
		if _, err := a.relay.WriteToUDP(out, f.client); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // the association is tearing down
			}
			// One undeliverable reply must not destroy the flow. A datagram whose
			// SOCKS header pushes it past the maximum UDP payload, or a transient
			// send-buffer error, costs that one reply — not the client's mapping.
			a.stats.AssociateReplyErrors.Add(1)
			continue
		}
	}
}

// acceptSource pins the client source on the first accepted datagram (subject
// to the ASSOCIATE request's declared source, if any) and rejects datagrams
// from any other source thereafter.
func (a *association) acceptSource(src *net.UDPAddr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		if a.expectIP != nil && !a.expectIP.IsUnspecified() && !a.expectIP.Equal(src.IP) {
			return false
		}
		if a.expectPort != 0 && a.expectPort != src.Port {
			return false
		}
		a.client = &net.UDPAddr{IP: append(net.IP(nil), src.IP...), Port: src.Port, Zone: src.Zone}
		return true
	}
	return a.client.Port == src.Port && a.client.IP.Equal(src.IP)
}

// removeFlow deletes the flow if it is still the registered one, then closes it.
func (a *association) removeFlow(f *udpFlow) {
	a.mu.Lock()
	if a.flows[f.key] == f {
		delete(a.flows, f.key)
	}
	a.mu.Unlock()
	f.close()
}

// evictLRULocked removes the least-recently-used flow from the table and returns
// it, for the caller to close outside the lock. Caller holds mu.
func (a *association) evictLRULocked() *udpFlow {
	var victim *udpFlow
	for _, f := range a.flows {
		if victim == nil || f.lastActive() < victim.lastActive() {
			victim = f
		}
	}
	if victim != nil {
		delete(a.flows, victim.key)
	}
	return victim
}

// closeAllFlows closes every flow, unblocking all reader goroutines.
func (a *association) closeAllFlows() {
	a.mu.Lock()
	flows := make([]*udpFlow, 0, len(a.flows))
	for _, f := range a.flows {
		flows = append(flows, f)
	}
	a.flows = make(map[string]*udpFlow)
	a.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
}
