// Package relay implements the bidirectional copy the proxies use, with
// cancellation that is guaranteed to unblock both reads and writes.
//
// Cancellation is subtle enough to be worth stating once, in one place, rather
// than re-deriving it per proxy. Poking read deadlines is NOT sufficient to tear
// a relay down:
//
//   - it cannot interrupt a goroutine blocked in Write;
//   - a one-shot poke is erased by the copy loop's next read-deadline re-arm, so
//     a stream carrying continuous data outlives its context; and
//   - it is a no-op on an endpoint with no deadline support at all, such as the
//     io.ReadWriter net/http hands back for a 101 upgrade.
//
// Close is the only mechanism that works for every endpoint, so on cancellation
// every endpoint is both deadline-poisoned and closed, and the copy loops stop
// re-arming deadlines once the context is done.
//
// Closing here is also what lets a caller's own `defer conn.Close()` run at all:
// a goroutine parked in Read or Write keeps Bidi from returning, so a deferred
// close that runs only after Bidi returns can never execute — a circular wait
// that leaks the goroutine and both endpoints permanently.
package proxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// aLongTimeAgo is a deadline in the distant past. Setting it forces an in-flight
// read or write to return immediately.
var aLongTimeAgo = time.Unix(1, 0)

var errInvalidWrite = errors.New("relay: invalid write result")

// relayBuffers supplies copy buffers.
type relayBuffers interface {
	Get() []byte
	Put([]byte)
}

// relayBufferSize is the copy buffer size for every proxy relay.
//
// It is deliberately small. A buffer is held for the whole lifetime of a relay
// direction — not just while bytes are moving — so at tens of thousands of
// concurrent connections the per-connection cost is what dominates, not the
// per-read syscall count. At 2kib a tunnel costs 4kib of buffer across its two
// directions; at the 32kib io.Copy defaults to it would cost 64kib, which is
// ~1.3GB at 20k concurrent tunnels against ~80MB here.
//
// 2kib is also the connect message pool's smallest size class (the largest is
// 4kib), so a larger buffer would not be pooled at all — it would allocate on
// every call.
const relayBufferSize = 2048

// messagePoolBuffers draws copy buffers from the shared connect message pool.
// Both proxies use it, so their per-connection memory cost cannot silently
// diverge.
type messagePoolBuffers struct{}

func (messagePoolBuffers) Get() []byte {
	return connect.MessagePoolGet(relayBufferSize)
}

func (messagePoolBuffers) Put(buf []byte) {
	connect.MessagePoolReturn(buf)
}

// relayEndpoint is one side of a relay. Reader and Writer are usually the same conn,
// but the client side may read through a buffered reader that already holds
// bytes consumed during the handshake.
type relayEndpoint struct {
	Reader io.Reader
	Writer io.Writer
}

// relayConfig tunes a relay.
type relayConfig struct {
	Buffers      relayBuffers
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// HalfClose propagates a clean end-of-stream in one direction as a CloseWrite
	// on the peer, leaving the other direction running — TCP half-close. Without
	// it, either direction ending tears the whole relay down, so a peer that
	// shuts down its write side to signal end-of-request never receives the
	// response. That idiom does not occur in HTTP (a request body is always
	// self-delimiting, so a client never needs to signal it with a FIN), but it
	// is common in the arbitrary TCP that a SOCKS proxy carries.
	//
	// It is honored ONLY when ReadTimeout is set, and deliberately so. Once we
	// have read EOF from a peer, TCP gives us no way to tell a half-close from
	// that peer subsequently vanishing: either way, reads just keep returning
	// EOF. So the surviving direction can only be bounded by an idle read
	// timeout. Without one, a half-closed tunnel whose upstream never answers
	// would park forever, which is precisely the leak this package exists to
	// prevent — so with no ReadTimeout we keep the safe full-teardown behavior.
	HalfClose bool
}

func (self *relayConfig) halfClose() bool {
	return self.HalfClose && 0 < self.ReadTimeout
}

type readDeadliner interface{ SetReadDeadline(time.Time) error }
type writeDeadliner interface{ SetWriteDeadline(time.Time) error }
type closeWriter interface{ CloseWrite() error }

// relayCopy copies src to dst until EOF, error, or ctx cancellation, applying
// readTimeout before each read and writeTimeout before each write when the
// endpoints support deadlines. flush, when non-nil, is called after each write.
//
// Deadlines are never re-armed once ctx is done, so a canceled copy cannot be
// kept alive indefinitely by a stream that keeps delivering data.
func relayCopy(
	ctx context.Context,
	dst io.Writer,
	src io.Reader,
	bufs relayBuffers,
	readTimeout time.Duration,
	writeTimeout time.Duration,
	flush func(),
) (written int64, err error) {
	buf := bufs.Get()
	defer bufs.Put(buf)

	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		if 0 < readTimeout {
			if c, ok := src.(readDeadliner); ok {
				c.SetReadDeadline(time.Now().Add(readTimeout))
			}
		}
		nr, er := src.Read(buf)
		if 0 < nr {
			if 0 < writeTimeout {
				if c, ok := dst.(writeDeadliner); ok {
					c.SetWriteDeadline(time.Now().Add(writeTimeout))
				}
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
			if flush != nil {
				flush()
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			return written, nil
		}
	}
}

// relayBidi copies in both directions between the a and b endpoints until the relay
// ends or ctx is canceled, then forces any parked direction to unwind.
//
// Without relayConfig.HalfClose, either direction ending cancels the relay and tears
// both endpoints down. With it, a direction that ends at a CLEAN end-of-stream
// instead forwards the FIN to the peer via CloseWrite and leaves the other
// direction running; the relay ends only when both directions are done. An
// error, or a peer that cannot CloseWrite, still tears everything down.
//
// It returns the first real error from either direction. A direction that ended
// at EOF reports nil, which must not mask the other direction's failure, and a
// cancellation is expected teardown rather than a failure.
func relayBidi(
	ctx context.Context,
	cancel context.CancelFunc,
	a relayEndpoint,
	b relayEndpoint,
	config relayConfig,
) error {
	halfClose := config.halfClose()

	errs := make(chan error, 2)

	// copyDir relays src->dst and then decides whether the relay as a whole is
	// over. It is the only place teardown is triggered by a direction ending.
	copyDir := func(dst io.Writer, src io.Reader) {
		_, err := relayCopy(ctx, dst, src, config.Buffers, config.ReadTimeout, config.WriteTimeout, nil)
		errs <- err
		if err == nil && halfClose {
			if closer, ok := dst.(closeWriter); ok {
				// a clean end of stream: pass the FIN through and let the peer keep
				// sending. The relay ends once BOTH directions are done.
				closer.CloseWrite()
				return
			}
		}
		cancel()
	}

	// Force any parked direction to unwind when ctx is canceled.
	//
	// context.AfterFunc does NOT hold a goroutine while it waits — it only starts
	// one if ctx actually fires. A `select { case <-ctx.Done(): }` watcher would
	// park a goroutine for the entire life of every connection, and a goroutine's
	// stack is the single largest per-connection memory item at scale.
	stop := context.AfterFunc(ctx, func() {
		relayForceUnblock(a.Reader, a.Writer, b.Reader, b.Writer)
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go connect.HandleError(func() {
		defer wg.Done()
		copyDir(b.Writer, a.Reader)
	})

	// The other direction runs on the CALLER's goroutine. Spawning one for each
	// direction would pay a second stack per connection for no benefit: the caller
	// is already a per-connection goroutine and has nothing else to do until the
	// relay ends.
	connect.HandleError(func() {
		copyDir(a.Writer, b.Reader)
	}, func() {
		// a panic here must still unblock the other direction, or wg.Wait hangs
		cancel()
	})

	wg.Wait()

	var returnErr error
	for i := 0; i < 2; i += 1 {
		select {
		case err := <-errs:
			if returnErr == nil && err != nil && !errors.Is(err, context.Canceled) {
				returnErr = err
			}
		default:
		}
	}
	return returnErr
}

// relayForceUnblock makes any in-flight read or write on the given endpoints return
// immediately: deadlines are poisoned for endpoints that support them, and
// io.Closers are closed, which is the only mechanism that reaches an endpoint
// with no deadline support. An endpoint passed twice (a conn used as both reader
// and writer) is simply closed twice, which is harmless.
func relayForceUnblock(endpoints ...any) {
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		if c, ok := endpoint.(readDeadliner); ok {
			c.SetReadDeadline(aLongTimeAgo)
		}
		if c, ok := endpoint.(writeDeadliner); ok {
			c.SetWriteDeadline(aLongTimeAgo)
		}
		if c, ok := endpoint.(io.Closer); ok {
			c.Close()
		}
	}
}
