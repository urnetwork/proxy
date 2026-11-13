// Virtual-time adjacent roots force deadline arms to complete after an owned
// cancellation poison. The three nil-idle copy modes use real net.Pipe I/O.
package proxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// A destination exposes a setter without giving this canceled copy ownership
// of its deadline. The copy must not touch it before a write arm occurs.
type adjacentUnusedDeadlineWriter struct {
	setCount atomic.Int64
}

// Accepts data only if a test unexpectedly reaches an ordinary write.
func (self *adjacentUnusedDeadlineWriter) Write(payload []byte) (int, error) {
	return len(payload), nil
}

// Makes unrelated deadline mutation observable without owning a connection.
func (self *adjacentUnusedDeadlineWriter) SetWriteDeadline(time.Time) error {
	self.setCount.Add(1)
	return nil
}

// With read idle disabled, a late write arm must still preserve cancellation.
func TestBidiSharedIdleZeroReadCancellationCannotRearmWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, ap := net.Pipe()
		b, bp := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		held := &sharedIdleDeadlineOnly{conn: b, gateWrite: true,
			entered: make(chan struct{}), release: make(chan struct{}), poisoned: make(chan struct{})}
		done, joined := make(chan error, 1), make(chan struct{})
		producerDone := make(chan struct{})
		defer func() {
			cancel()
			_ = a.Close()
			_ = ap.Close()
			_ = b.Close()
			_ = bp.Close()
			<-joined
			<-producerDone
		}()
		go func() {
			defer close(joined)
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: a, Writer: a}, relayEndpoint{Reader: held, Writer: held},
				relayConfig{Buffers: ownershipBuffers{}, ReadTimeout: 0, WriteTimeout: 15 * time.Second})
		}()
		go func() { defer close(producerDone); _, _ = ap.Write([]byte{1}) }()
		<-held.entered
		cancel()
		<-held.poisoned
		// Finish the actual cancellation callback before releasing the held arm,
		// so an old write cannot be rescued by a later poison.
		synctest.Wait()
		close(held.release)
		synctest.Wait()
		held.stateLock.Lock()
		writes, deadline := held.writeCalls, held.write
		held.stateLock.Unlock()
		if writes != 0 || deadline != aLongTimeAgo {
			t.Fatalf("canceled zero-read-timeout relay entered Write after late arm: writes=%d poisoned=%t", writes, deadline == aLongTimeAgo)
		}
		select {
		case <-done:
		default:
			t.Fatal("canceled zero-read-timeout relay retained an I/O wait")
		}
	})
}

// A standalone per-read deadline cannot overwrite its explicit cancellation
// owner's poison and then enter Read. No unrelated writer setter is touched.
func TestRelayCopyStandaloneCancellationCannotRearmRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source, peer := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		held := &sharedIdleDeadlineOnly{conn: source, gateRead: true,
			entered: make(chan struct{}), release: make(chan struct{}), poisoned: make(chan struct{})}
		writer := &adjacentUnusedDeadlineWriter{}
		joinPoison := afterFuncAndJoin(ctx, func() { relayForceUnblock(held) })
		done, joined := make(chan error, 1), make(chan struct{})
		defer func() {
			cancel()
			_ = source.Close()
			_ = peer.Close()
			<-joined
			joinPoison()
		}()
		go func() {
			defer close(joined)
			_, err := relayCopy(ctx, writer, held, ownershipBuffers{}, 30*time.Second, 15*time.Second, nil)
			done <- err
		}()
		<-held.entered
		cancel()
		joinPoison()
		close(held.release)
		synctest.Wait()
		held.stateLock.Lock()
		reads, deadline := held.readCalls, held.read
		held.stateLock.Unlock()
		if reads != 0 || deadline != aLongTimeAgo {
			t.Fatalf("canceled standalone copy entered Read after late arm: reads=%d poisoned=%t", reads, deadline == aLongTimeAgo)
		}
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("standalone read cancellation changed cause: %v", err)
		}
		if writer.setCount.Load() != 0 {
			t.Fatal("canceled read poisoned an unrelated writer deadline")
		}
	})
}

// A successful read does not license a write after cancellation wins the
// write-deadline arm. A zero read timeout never grants read-deadline ownership.
func TestRelayCopyStandaloneCancellationCannotRearmWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, ap := net.Pipe()
		b, bp := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		source := &sharedIdleDeadlineOnly{conn: a}
		held := &sharedIdleDeadlineOnly{conn: b, gateWrite: true,
			entered: make(chan struct{}), release: make(chan struct{}), poisoned: make(chan struct{})}
		joinPoison := afterFuncAndJoin(ctx, func() { relayForceUnblock(held) })
		done, joined := make(chan error, 1), make(chan struct{})
		producerDone := make(chan struct{})
		defer func() {
			cancel()
			_ = a.Close()
			_ = ap.Close()
			_ = b.Close()
			_ = bp.Close()
			<-joined
			<-producerDone
			joinPoison()
		}()
		go func() {
			defer close(joined)
			_, err := relayCopy(ctx, held, source, ownershipBuffers{}, 0, 15*time.Second, nil)
			done <- err
		}()
		go func() { defer close(producerDone); _, _ = ap.Write([]byte{1}) }()
		<-held.entered
		cancel()
		joinPoison()
		close(held.release)
		synctest.Wait()
		held.stateLock.Lock()
		writes, deadline := held.writeCalls, held.write
		held.stateLock.Unlock()
		if writes != 0 || deadline != aLongTimeAgo {
			t.Fatalf("canceled standalone copy entered Write after late arm: writes=%d poisoned=%t", writes, deadline == aLongTimeAgo)
		}
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("standalone write cancellation changed cause: %v", err)
		}
		if !source.read.IsZero() || !source.write.IsZero() {
			t.Fatal("zero-read-timeout copy poisoned an unrelated source deadline")
		}
		// An already canceled copy must not program an endpoint merely because
		// it advertises deadline methods.
		untouched := &sharedIdleDeadlineOnly{conn: a}
		unusedWriter := &adjacentUnusedDeadlineWriter{}
		_, err := relayCopy(ctx, unusedWriter, untouched, ownershipBuffers{}, 30*time.Second, 15*time.Second, nil)
		if !errors.Is(err, context.Canceled) || !untouched.read.IsZero() || !untouched.write.IsZero() || unusedWriter.setCount.Load() != 0 {
			t.Fatal("already canceled copy claimed unrelated deadline ownership")
		}
	})
}
