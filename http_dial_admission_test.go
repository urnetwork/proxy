// Pins the ownership transition between sampling request cancellation and
// acquiring the callback-admission gate.
package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// Holds a cancellation read after it has sampled the live context. This models
// a dial worker descheduled immediately before the owner gate is acquired.
type httpDialSampledContext struct {
	context.Context
	entered chan struct{}
	release chan struct{}
}

// Returns the cancellation state sampled before the explicit scheduling gap.
func (self *httpDialSampledContext) Err() error {
	err := self.Context.Err()
	close(self.entered)
	<-self.release
	return err
}

// Closing a zero-worker owner must reject a worker whose earlier cancellation
// sample was still live; the gate is the atomic ownership boundary.
func TestHttpDialOwnerSealsSampledAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newHttpDialOwner(context.Background())
		ctx := &httpDialSampledContext{Context: owner.ctx, entered: make(chan struct{}), release: make(chan struct{})}
		owner.ctx = ctx
		workerDone := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(ctx.release) })
		var calls atomic.Int32
		var dialErr error
		go func() {
			defer close(workerDone)
			_, dialErr = owner.dial(func(context.Context) (net.Conn, error) {
				calls.Add(1)
				return nil, context.Canceled
			})
		}()
		defer func() {
			unblock()
			joinHttpDialTestWorkers(t, workerDone)
		}()
		awaitHttpDialTestEvent(t, ctx.entered)
		owner.closeAndWait(func() {})
		unblock()
		awaitHttpDialTestEvent(t, workerDone)
		if calls.Load() != 0 || !errors.Is(dialErr, context.Canceled) {
			t.Errorf("sealed owner admitted authentication after its live cancellation sample: calls=%d, err=%v", calls.Load(), dialErr)
		}
	})
}
