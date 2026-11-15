package proxy

import (
	"context"
	"net"
	"sync"
)

// drainState coordinates a graceful drain across a proxy's listeners and
// in-flight connections (PROXYDRAIN1.md §3.2).
//
// Drain stops the accept side: registered listeners close and new requests
// on already-accepted connections are refused. In-flight connections keep
// relaying under the caller's still-live ctx; the caller ends the drain by
// canceling that ctx, which stays the one hard teardown, after the active
// count reaches zero or a deadline passes.
//
// This maps to a warpctl deploy: the DNAT flip already steers new flows to
// the replacement container, so by the time the old container drains, only
// conntrack-pinned established flows still arrive here — exactly the
// connections drain keeps alive.
//
// The zero value is ready to use (embed by value), so struct-literal
// construction — which the tests use for socksServer — works without an
// init hook.
type drainState struct {
	stateLock sync.Mutex
	draining  bool
	listeners []net.Listener
	active    int
	// notify is closed and replaced on every transition observable by
	// WaitIdle (drain start, active count reaching zero); created lazily to
	// keep the zero value usable
	notify chan struct{}
}

// registerListener adds a listener to be closed when the drain begins.
// If the drain has already begun, the listener is closed immediately and
// registerListener returns false; the caller should not serve it.
func (self *drainState) registerListener(l net.Listener) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.draining {
		l.Close()
		return false
	}
	self.listeners = append(self.listeners, l)
	return true
}

// unregisterListener removes a listener whose serve loop has ended, so the
// registry stays bounded for callers that serve and stop repeatedly.
func (self *drainState) unregisterListener(l net.Listener) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, l2 := range self.listeners {
		if l2 == l {
			self.listeners[i] = self.listeners[len(self.listeners)-1]
			self.listeners = self.listeners[:len(self.listeners)-1]
			return
		}
	}
}

// Drain begins the drain: all registered listeners close and Draining
// reports true. Idempotent.
func (self *drainState) Drain() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.draining {
		return
	}
	self.draining = true
	for _, l := range self.listeners {
		l.Close()
	}
	self.listeners = nil
	self.notifyWithLock()
}

func (self *drainState) Draining() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.draining
}

// tryEnter atomically admits and accounts work. Once Drain has observed and
// set draining, no request/accepted connection can increment active afterward;
// this closes the check-then-enter window where WaitIdle could return between
// those two operations.
func (self *drainState) tryEnter() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.draining {
		return false
	}
	self.active += 1
	return true
}

func (self *drainState) exit() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.active -= 1
	if self.active == 0 {
		self.notifyWithLock()
	}
}

func (self *drainState) ActiveCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.active
}

func (self *drainState) notifyWithLock() {
	if self.notify != nil {
		close(self.notify)
		self.notify = nil
	}
}

func (self *drainState) notifyChanWithLock() chan struct{} {
	if self.notify == nil {
		self.notify = make(chan struct{})
	}
	return self.notify
}

// WaitIdle blocks until the drain has begun and no connections are active,
// or ctx is done. It returns true when idle was reached.
func (self *drainState) WaitIdle(ctx context.Context) bool {
	for {
		idle, notify := func() (bool, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.draining && self.active == 0, self.notifyChanWithLock()
		}()
		if idle {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-notify:
		}
	}
}
