// Exercises cancellation and joining when either actual relay direction unwinds abnormally.
package proxy

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"testing/synctest"

	"github.com/urnetwork/connect"
)

// Aborts only after the opposite direction has entered its owned socket read.
type ownershipAbortReader struct {
	before     <-chan struct{}
	goexit     bool
	panicValue string
}

// A recognized cancellation panic keeps the probe independent of process logging.
func (self *ownershipAbortReader) Read([]byte) (int, error) {
	if self.before != nil {
		<-self.before
	}
	if self.goexit {
		runtime.Goexit()
	}
	panic(self.panicValue)
}

// A spawned copy's panic must unblock the caller's copy.
func TestServeOwnershipRelaySpawnedPanicCancelsPeer(t *testing.T) {
	ownershipRelaySpawnedUnwind(t, false)
}

// Goexit bypasses recovery callbacks, so cancellation must be owned by a defer.
func TestServeOwnershipRelaySpawnedGoexitCancelsPeer(t *testing.T) {
	ownershipRelaySpawnedUnwind(t, true)
}

// Retains the existing caller-direction panic behavior while checking its peer join.
func TestServeOwnershipRelayCallerPanicJoinsPeer(t *testing.T) {
	ownershipRelayCallerUnwind(t, false)
}

// The caller's Goexit must run a full cancel-and-join scope before its goroutine ends.
func TestServeOwnershipRelayCallerGoexitJoinsPeer(t *testing.T) {
	ownershipRelayCallerUnwind(t, true)
}

// Checks that a failed spawned producer cannot leave its sibling parked forever.
func ownershipRelaySpawnedUnwind(t *testing.T, goexit bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()
		peer := &ownershipReadTailConn{Conn: serverConn, readEntered: make(chan struct{}), tailEntered: make(chan struct{}), tailRelease: make(chan struct{}), tailDone: make(chan struct{})}
		close(peer.tailRelease)
		aborting := &ownershipAbortReader{before: peer.readEntered, goexit: goexit, panicValue: "Done"}
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: aborting, Writer: io.Discard}, relayEndpoint{Reader: peer, Writer: io.Discard}, relayConfig{Buffers: ownershipBuffers{}})
		}()
		synctest.Wait()
		if ctx.Err() == nil {
			t.Error("spawned direction unwind did not cancel its parked peer")
			cancel()
		}
		<-done
		<-peer.tailDone
	})
}

// Holds a provider read tail to distinguish cancellation from actual worker completion.
func ownershipRelayCallerUnwind(t *testing.T, goexit bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()
		peer := &ownershipReadTailConn{Conn: serverConn, readEntered: make(chan struct{}), tailEntered: make(chan struct{}), tailRelease: make(chan struct{}), tailDone: make(chan struct{})}
		aborting := &ownershipAbortReader{before: peer.readEntered, goexit: goexit, panicValue: "Done"}
		done := make(chan error, 1)
		go func() {
			defer func() { done <- nil }()
			relayBidi(ctx, cancel, relayEndpoint{Reader: peer, Writer: io.Discard}, relayEndpoint{Reader: aborting, Writer: io.Discard}, relayConfig{Buffers: ownershipBuffers{}})
		}()
		synctest.Wait()
		if ctx.Err() == nil {
			t.Error("caller direction unwind did not cancel its parked peer")
			cancel()
			// The broken scope stopped its AfterFunc, so fresh rescue cannot rely on it.
			serverConn.Close()
		}
		<-peer.tailEntered
		waiting := ownershipMustStillRun(t, done, "relay caller unwind")
		close(peer.tailRelease)
		if waiting {
			<-done
		}
		<-peer.tailDone
	})
}

// Holds the recovery function itself after a worker's inner function has unwound.
type ownershipWarningLogger struct {
	connect.Logger
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
}

// Models a synchronous recovery logger whose resources remain in use until return.
func (self *ownershipWarningLogger) Warningf(string, ...any) {
	close(self.entered)
	<-self.release
	close(self.done)
}

// The spawned direction's completion must include recovery and logging, not only its copy closure.
func TestServeOwnershipRelayJoinsRecoveryTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := connect.DefaultLogger()
		logger := &ownershipWarningLogger{Logger: connect.NewNoopLogger(), entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
		connect.SetDefaultLogger(logger)
		defer connect.SetDefaultLogger(previous)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		aborting := &ownershipAbortReader{panicValue: "synthetic relay read panic"}
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: aborting, Writer: io.Discard}, relayEndpoint{Reader: &ownershipAbortReader{before: logger.entered, panicValue: "Done"}, Writer: io.Discard}, relayConfig{Buffers: ownershipBuffers{}})
		}()
		<-logger.entered
		waiting := ownershipMustStillRun(t, done, "relay recovery logger")
		close(logger.release)
		if waiting {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		<-logger.done
	})
}

// The client reader's completion must similarly include the enclosing recovery function.
func TestServeOwnershipClientWatchJoinsRecoveryTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := connect.DefaultLogger()
		logger := &ownershipWarningLogger{Logger: connect.NewNoopLogger(), entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
		connect.SetDefaultLogger(logger)
		defer connect.SetDefaultLogger(previous)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()
		conn := &ownershipPanickingConn{Conn: serverConn}
		watch := watchClientClose(ctx, cancel, conn)
		<-logger.entered
		done := make(chan error, 1)
		go func() { watch.stop(); done <- nil }()
		waiting := ownershipMustStillRun(t, done, "client watch recovery logger")
		close(logger.release)
		if waiting {
			<-done
		}
		<-logger.done
	})
}

// Isolates a failed reader from deadline/close methods still needed by its owner.
type ownershipPanickingConn struct{ net.Conn }

// The synthetic panic is recovered by the real watchClientClose implementation.
func (self *ownershipPanickingConn) Read([]byte) (int, error) { panic("synthetic client read panic") }
