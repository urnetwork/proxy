// Pins both half-close directions while abnormal-unwind joins are active.
package proxy

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Records a forwarded write-side eof without closing the peer read side.
type ownershipHalfWriter struct {
	closed chan struct{}
	once   sync.Once
}

// No payload bytes are needed to check the half-close ownership transition.
func (self *ownershipHalfWriter) Write(data []byte) (int, error) { return len(data), nil }

// Signals the fin forwarded by one completed direction.
func (self *ownershipHalfWriter) CloseWrite() error {
	self.once.Do(func() { close(self.closed) })
	return nil
}

// A clean spawned-direction eof must leave the caller direction alive.
func TestServeOwnershipRelaySpawnedHalfClosePreservesPeer(t *testing.T) {
	ownershipRelayHalfClose(t, true)
}

// A clean caller-direction eof must leave the spawned direction alive.
func TestServeOwnershipRelayCallerHalfClosePreservesPeer(t *testing.T) {
	ownershipRelayHalfClose(t, false)
}

// Checks the existing eof policy at the actual relay scope with no timers or socket scheduling.
func ownershipRelayHalfClose(t *testing.T, spawnedFirst bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a := &ownershipRelayReader{readEntered: make(chan struct{}), readRelease: make(chan struct{})}
		b := &ownershipRelayReader{readEntered: make(chan struct{}), readRelease: make(chan struct{})}
		aw := &ownershipHalfWriter{closed: make(chan struct{})}
		bw := &ownershipHalfWriter{closed: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: a, Writer: aw}, relayEndpoint{Reader: b, Writer: bw}, relayConfig{Buffers: ownershipBuffers{}, ReadTimeout: time.Minute, HalfClose: true})
		}()
		<-a.readEntered
		<-b.readEntered
		if spawnedFirst {
			close(a.readRelease)
			<-bw.closed
		} else {
			close(b.readRelease)
			<-aw.closed
		}
		waiting := ownershipMustStillRun(t, done, "healthy half-close peer")
		if ctx.Err() != nil {
			t.Error("clean one-direction eof canceled the peer")
		}
		if spawnedFirst {
			close(b.readRelease)
		} else {
			close(a.readRelease)
		}
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		<-aw.closed
		<-bw.closed
	})
}
