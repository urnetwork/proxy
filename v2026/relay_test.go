package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// testBuffers is pool-backed like the real proxies', so benchmarks measure the
// copy loop's allocations rather than the test double's.
type testBuffers struct{}

func (testBuffers) Get() []byte {
	bp := testPool.Get().(*[]byte)
	return *bp
}

func (testBuffers) Put(b []byte) {
	testPool.Put(&b)
}

// blockingEndpoint blocks in Read and Write until it is closed. It deliberately
// has NO deadline methods, mirroring the io.ReadWriter net/http hands back for a
// 101 upgrade: closing it is the only thing that can unblock it. A relay that
// tears down by poking read deadlines hangs on this forever.
type blockingEndpoint struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newBlockingEndpoint() *blockingEndpoint {
	return &blockingEndpoint{closed: make(chan struct{})}
}

func (self *blockingEndpoint) Read(p []byte) (int, error) {
	<-self.closed
	return 0, io.EOF
}

func (self *blockingEndpoint) Write(p []byte) (int, error) {
	<-self.closed
	return 0, io.ErrClosedPipe
}

func (self *blockingEndpoint) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

// infiniteReader always has data, so a copy loop reading from it never parks and
// keeps re-arming its read deadline.
type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// deadlineOnlyEndpoint supports deadlines but is not an io.Closer, so it can only
// be unblocked by deadline poisoning.
type deadlineOnlyEndpoint struct {
	mu       sync.Mutex
	deadline time.Time
}

func (self *deadlineOnlyEndpoint) SetReadDeadline(t time.Time) error {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.deadline = t
	return nil
}

func (self *deadlineOnlyEndpoint) Read(p []byte) (int, error) {
	for {
		self.mu.Lock()
		deadline := self.deadline
		self.mu.Unlock()
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return 0, errors.New("deadline exceeded")
		}
		time.Sleep(time.Millisecond)
	}
}

func mustReturn(t *testing.T, name string, d time.Duration, run func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		run()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s: a goroutine is parked with no way to be unblocked", name, d)
	}
}

// TestBidiCancelUnblocksBlockedWrite is the regression test for the circular
// wait: a copy goroutine parked in Write cannot be unblocked by a read-deadline
// poke, so Bidi would never return, so the caller's deferred Close (the only
// thing that could unblock the Write) could never run.
func TestBidiCancelUnblocksBlockedWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// aReader always has data and bWriter never accepts it, so the a->b direction
	// parks in Write.
	blocking := newBlockingEndpoint()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	mustReturn(t, "Bidi with a blocked write", 5*time.Second, func() {
		relayBidi(ctx, cancel, relayEndpoint{Reader: infiniteReader{}, Writer: io.Discard}, relayEndpoint{Reader: blocking, Writer: blocking}, relayConfig{Buffers: testBuffers{}, ReadTimeout: 0, WriteTimeout: 0})
	})
}

// TestBidiCancelUnblocksEndpointWithoutDeadlines is the regression test for the
// 101-upgrade leak: the upstream endpoint supports no deadlines at all, so only
// Close can unblock a read parked on it.
func TestBidiCancelUnblocksEndpointWithoutDeadlines(t *testing.T) {
	client, clientPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()

	upstream := newBlockingEndpoint()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	mustReturn(t, "Bidi with a deadline-less endpoint", 5*time.Second, func() {
		relayBidi(ctx, cancel, relayEndpoint{Reader: client, Writer: client}, relayEndpoint{Reader: upstream, Writer: upstream}, relayConfig{Buffers: testBuffers{}, ReadTimeout: 0, WriteTimeout: 0})
	})
}

// TestBidiCancelStopsContinuousStream is the regression test for the deadline
// re-arm: the copy loop used to overwrite the cancellation poke with a fresh
// now+readTimeout deadline on every iteration, so a relay carrying continuous
// data would keep running long after its context was canceled (e.g. a transfer
// that survives server shutdown).
func TestBidiCancelStopsContinuousStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	blocking := newBlockingEndpoint()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// a generous read timeout: the relay must stop because of the cancellation,
	// not because the timeout eventually fires
	mustReturn(t, "Bidi carrying a continuous stream", 5*time.Second, func() {
		relayBidi(ctx, cancel, relayEndpoint{Reader: infiniteReader{}, Writer: io.Discard}, relayEndpoint{Reader: blocking, Writer: blocking}, relayConfig{Buffers: testBuffers{}, ReadTimeout: 10 * time.Minute, WriteTimeout: 0})
	})
}

// TestBidiCancelPoisonsDeadlineOnlyEndpoint covers an endpoint that is not an
// io.Closer: deadline poisoning must still unblock it.
func TestBidiCancelPoisonsDeadlineOnlyEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	mustReturn(t, "Bidi with a deadline-only endpoint", 5*time.Second, func() {
		relayBidi(ctx, cancel, relayEndpoint{Reader: &deadlineOnlyEndpoint{}, Writer: io.Discard}, relayEndpoint{Reader: &deadlineOnlyEndpoint{}, Writer: io.Discard}, relayConfig{Buffers: testBuffers{}, ReadTimeout: 0, WriteTimeout: 0})
	})
}

type errReader struct{ err error }

func (self errReader) Read(p []byte) (int, error) { return 0, self.err }

// gatedErrReader announces when it has entered Read, then fails with err once
// released. Its error therefore originates from a read already in flight, which
// no context check can preempt.
type gatedErrReader struct {
	entered   chan struct{}
	release   chan struct{}
	err       error
	enterOnce sync.Once
}

func (self *gatedErrReader) Read(p []byte) (int, error) {
	self.enterOnce.Do(func() { close(self.entered) })
	<-self.release
	return 0, self.err
}

// gatedEofReader ends cleanly once released.
type gatedEofReader struct{ release chan struct{} }

func (self *gatedEofReader) Read(p []byte) (int, error) {
	<-self.release
	return 0, io.EOF
}

// TestBidiReportsRealErrorOverEOF is the regression test for error precedence.
// The direction that ends at EOF reports nil, and returning whichever result was
// queued FIRST silently dropped the other direction's real failure. Here the EOF
// (nil) is queued first by construction, so a Bidi that returns nil is repeating
// the bug.
func TestBidiReportsRealErrorOverEOF(t *testing.T) {
	sentinel := errors.New("upstream exploded")

	failing := &gatedErrReader{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		err:     sentinel,
	}
	ending := &gatedEofReader{release: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// no endpoint is a Closer or a deadline setter, so teardown cannot inject an
	// error of its own and mask what the directions actually reported
	result := make(chan error, 1)
	go func() {
		result <- relayBidi(ctx, cancel, relayEndpoint{Reader: ending, Writer: io.Discard}, relayEndpoint{Reader: failing, Writer: io.Discard}, relayConfig{Buffers: testBuffers{}, ReadTimeout: 0, WriteTimeout: 0})
	}()

	<-failing.entered     // the failing direction is parked inside Read
	close(ending.release) // the other direction ends at EOF, reporting nil, and cancels
	time.Sleep(100 * time.Millisecond)
	close(failing.release) // only now does the in-flight read produce the real error

	select {
	case err := <-result:
		if !errors.Is(err, sentinel) {
			t.Fatalf("Bidi err = %v, want %v (an EOF on one side must not mask the other side's failure)", err, sentinel)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Bidi did not return")
	}
}

// TestBidiRelaysBothDirections is the basic correctness check.
func TestBidiRelaysBothDirections(t *testing.T) {
	clientConn, client := net.Pipe()
	upstreamConn, upstream := net.Pipe()
	defer clientConn.Close()
	defer upstreamConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go relayBidi(ctx, cancel, relayEndpoint{Reader: client, Writer: client}, relayEndpoint{Reader: upstream, Writer: upstream}, relayConfig{Buffers: testBuffers{}, ReadTimeout: 0, WriteTimeout: 0})

	clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	upstreamConn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(upstreamConn, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("upstream got %q, want ping", buf)
	}

	if _, err := upstreamConn.Write([]byte("pong")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q, want pong", buf)
	}
}

// TestCopyStopsOnCancel checks the single-direction copy honors cancellation even
// while data keeps arriving.
func TestCopyStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	mustReturn(t, "Copy of a continuous stream", 5*time.Second, func() {
		relayCopy(ctx, io.Discard, infiniteReader{}, testBuffers{}, time.Minute, 0, nil)
	})
}

// pooledBuffers reports whether every buffer it hands out is returned, so a copy
// path that drops one on an error branch is caught.
type pooledBuffers struct {
	mu   sync.Mutex
	live int
	max  int
}

func (self *pooledBuffers) Get() []byte {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.live += 1
	if self.max < self.live {
		self.max = self.live
	}
	return make([]byte, 32*1024)
}

func (self *pooledBuffers) Put(b []byte) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.live -= 1
}

// TestCopyAlwaysReturnsItsBuffer checks every exit path returns the buffer,
// including the cancellation and error paths, since a leaked pool buffer is a
// slow memory leak under load.
func TestCopyAlwaysReturnsItsBuffer(t *testing.T) {
	bufs := &pooledBuffers{}

	// normal EOF
	relayCopy(context.Background(), io.Discard, errReader{io.EOF}, bufs, 0, 0, nil)
	// read error
	relayCopy(context.Background(), io.Discard, errReader{errors.New("boom")}, bufs, 0, 0, nil)
	// cancellation
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	relayCopy(canceled, io.Discard, infiniteReader{}, bufs, 0, 0, nil)
	// write error
	relayCopy(context.Background(), errWriter{errors.New("boom")}, infiniteReader{}, bufs, 0, 0, nil)

	bufs.mu.Lock()
	defer bufs.mu.Unlock()
	if bufs.live != 0 {
		t.Fatalf("%d copy buffers were never returned to the pool", bufs.live)
	}
	if bufs.max == 0 {
		t.Fatal("no buffers were taken; the test is not exercising the copy path")
	}
}

type errWriter struct{ err error }

func (self errWriter) Write(p []byte) (int, error) { return 0, self.err }

// BenchmarkCopy measures the steady-state relay throughput and, importantly, the
// per-copy allocation count: the copy loop must not allocate per read/write, or
// tens of thousands of concurrent relays would bury the GC.
func BenchmarkCopy(b *testing.B) {
	payload := make([]byte, 32*1024)
	bufs := testBuffers{}
	ctx := context.Background()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i += 1 {
		src := &limitedReader{payload: payload, remaining: 32}
		if _, err := relayCopy(ctx, io.Discard, src, bufs, 0, 0, nil); err != nil {
			b.Fatalf("copy: %v", err)
		}
	}
}

// limitedReader yields payload a fixed number of times, then EOF.
type limitedReader struct {
	payload   []byte
	remaining int
}

func (self *limitedReader) Read(p []byte) (int, error) {
	if self.remaining <= 0 {
		return 0, io.EOF
	}
	self.remaining -= 1
	return copy(p, self.payload), nil
}

// --- half-close -----------------------------------------------------------

// tcpPair returns a connected pair of REAL tcp conns. net.Pipe cannot be used
// for half-close tests: its Close tears down both directions at once, which is
// exactly the thing a half-close is not.
func tcpPair(t *testing.T) (peer net.Conn, local net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	peer, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	local = <-accepted
	if local == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		peer.Close()
		local.Close()
	})
	return peer, local
}

// halfCloseConn records CloseWrite and forwards it, so a test can see whether the
// relay propagated the FIN instead of tearing the tunnel down.
type halfCloseConn struct {
	net.Conn
	closeWrites atomic.Int64
	eof         chan struct{}
	eofOnce     sync.Once
}

func (self *halfCloseConn) CloseWrite() error {
	self.closeWrites.Add(1)
	self.eofOnce.Do(func() { close(self.eof) })
	if closer, ok := self.Conn.(closeWriter); ok {
		return closer.CloseWrite()
	}
	return nil
}

// TestBidiHalfClosePropagatesFin covers the SOCKS case: a peer that ends its
// write side cleanly must have that FIN forwarded to the other side, and the
// other direction must keep running so the response can still come back.
func TestBidiHalfClosePropagatesFin(t *testing.T) {
	clientPeer, client := tcpPair(t)
	upstreamPeer, upstreamRaw := tcpPair(t)
	upstream := &halfCloseConn{Conn: upstreamRaw, eof: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- relayBidi(ctx, cancel,
			relayEndpoint{Reader: client, Writer: client},
			relayEndpoint{Reader: upstream, Writer: upstream},
			relayConfig{Buffers: testBuffers{}, ReadTimeout: 5 * time.Second, HalfClose: true},
		)
	}()

	// the client sends its request and then ends ONLY its write side
	if _, err := clientPeer.Write([]byte("REQUEST")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := clientPeer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}

	buf := make([]byte, 7)
	upstreamPeer.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(upstreamPeer, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf) != "REQUEST" {
		t.Fatalf("upstream got %q", buf)
	}

	// the FIN must reach the upstream rather than the relay collapsing
	select {
	case <-upstream.eof:
	case <-time.After(3 * time.Second):
		t.Fatal("the client's half-close was not propagated to the upstream")
	}
	if n := upstream.closeWrites.Load(); n != 1 {
		t.Fatalf("CloseWrite called %d times, want 1", n)
	}

	// and the upstream must still be able to answer
	if _, err := upstreamPeer.Write([]byte("RESPONSE")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	resp := make([]byte, 8)
	clientPeer.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(clientPeer, resp); err != nil {
		t.Fatalf("the response was dropped after the client half-closed: %v", err)
	}
	if string(resp) != "RESPONSE" {
		t.Fatalf("client got %q, want RESPONSE", resp)
	}

	// once the upstream also ends, the relay is over
	upstreamPeer.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Bidi did not return once both directions ended")
	}
}

// TestBidiHalfCloseRequiresReadTimeout pins the safety gate. Once we have read
// EOF from a peer, TCP cannot tell a half-close from that peer vanishing, so the
// surviving direction is bounded only by an idle read timeout. With no timeout
// set, half-close must NOT be honored — otherwise a client that simply went away
// while its upstream is silent would park the relay forever.
func TestBidiHalfCloseRequiresReadTimeout(t *testing.T) {
	upstream := newBlockingEndpoint() // silent forever, and no deadline support
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// the client ends immediately; with HalfClose honored and no read timeout the
	// relay would wait on the silent upstream forever
	mustReturn(t, "Bidi half-close with no read timeout", 5*time.Second, func() {
		relayBidi(ctx, cancel,
			relayEndpoint{Reader: errReader{io.EOF}, Writer: io.Discard},
			relayEndpoint{Reader: upstream, Writer: upstream},
			relayConfig{Buffers: testBuffers{}, HalfClose: true}, // ReadTimeout unset
		)
	})
}

// TestBidiHalfCloseBoundedByReadTimeout checks the surviving direction is still
// reclaimed when the upstream never answers a half-closed client.
func TestBidiHalfCloseBoundedByReadTimeout(t *testing.T) {
	_, upstream := net.Pipe() // a real conn: silent, but honors deadlines
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mustReturn(t, "Bidi half-close against a silent upstream", 5*time.Second, func() {
		relayBidi(ctx, cancel,
			relayEndpoint{Reader: errReader{io.EOF}, Writer: io.Discard},
			relayEndpoint{Reader: upstream, Writer: upstream},
			relayConfig{Buffers: testBuffers{}, ReadTimeout: 300 * time.Millisecond, HalfClose: true},
		)
	})
}

// TestBidiHalfCloseFallsBackWhenUnsupported: an endpoint with no CloseWrite (the
// http upgrade body, say) must still get the full-teardown behavior rather than
// hanging.
func TestBidiHalfCloseFallsBackWhenUnsupported(t *testing.T) {
	upstream := newBlockingEndpoint() // io.Closer, but no CloseWrite
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mustReturn(t, "Bidi half-close onto an endpoint without CloseWrite", 5*time.Second, func() {
		relayBidi(ctx, cancel,
			relayEndpoint{Reader: errReader{io.EOF}, Writer: io.Discard},
			relayEndpoint{Reader: upstream, Writer: upstream},
			relayConfig{Buffers: testBuffers{}, ReadTimeout: 5 * time.Second, HalfClose: true},
		)
	})
}

// TestMessagePoolBuffersSize pins the per-connection buffer cost. A relay holds
// its buffer for the life of the connection, so this constant is what decides how
// many concurrent tunnels fit in a memory budget.
func TestMessagePoolBuffersSize(t *testing.T) {
	bufs := messagePoolBuffers{}
	buf := bufs.Get()
	defer bufs.Put(buf)
	if len(buf) != relayBufferSize {
		t.Fatalf("relay buffer = %d bytes, want %d", len(buf), relayBufferSize)
	}
	if relayBufferSize != 2048 {
		t.Fatalf("relayBufferSize = %d: a relay direction holds this for the whole connection, "+
			"so raising it multiplies memory across every concurrent tunnel", relayBufferSize)
	}
}
