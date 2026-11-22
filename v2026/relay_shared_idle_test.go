// Virtual-time regressions exercise actual relayBidi over in-process pipes.
// No socket, wall-clock sleep, process-global packet pool or fixture is used.
package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Owns the actual relay, peers and all underlying pipe lifetimes in one bubble.
type sharedIdleRelayFixture struct {
	ctx        context.Context
	cancel     context.CancelFunc
	clientPeer net.Conn
	originPeer net.Conn
	raw        []net.Conn
	done       chan error
	joined     chan struct{}
}

// TLS handshakes complete before the relay starts applying its idle policy.
func newSharedIdleRelayFixture(t *testing.T, frontendTls bool, writeTimeout time.Duration) *sharedIdleRelayFixture {
	t.Helper()
	client, clientPeer := net.Pipe()
	origin, originPeer := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	f := &sharedIdleRelayFixture{ctx: ctx, cancel: cancel, clientPeer: clientPeer, originPeer: originPeer,
		raw: []net.Conn{client, clientPeer, origin, originPeer}, done: make(chan error, 1), joined: make(chan struct{})}
	var clientReader net.Conn = client
	if frontendTls {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.example"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		server := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: key}}, SessionTicketsDisabled: true})
		peer := tls.Client(clientPeer, &tls.Config{InsecureSkipVerify: true, ServerName: "relay.example"})
		handshake := make(chan error, 1)
		go func() { handshake <- server.HandshakeContext(ctx) }()
		if err := peer.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-handshake; err != nil {
			t.Fatal(err)
		}
		clientReader, f.clientPeer = server, peer
	}
	go func() {
		defer close(f.joined)
		f.done <- relayBidi(ctx, cancel,
			relayEndpoint{Reader: clientReader, Writer: clientReader},
			relayEndpoint{Reader: origin, Writer: origin},
			relayConfig{Buffers: ownershipBuffers{}, ReadTimeout: 30 * time.Second, WriteTimeout: writeTimeout})
	}()
	return f
}

// Even a fatal assertion must release and join the relay before bubble exit.
func (self *sharedIdleRelayFixture) close() {
	self.cancel()
	for _, conn := range self.raw {
		_ = conn.Close()
	}
	<-self.joined
}

// Exact periodic progress advances virtual time instead of keeping a hot loop
// runnable. Twenty ticks span more than three default read-idle intervals.
func sharedIdleOneWay(t *testing.T, upload, frontendTls bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		f := newSharedIdleRelayFixture(t, frontendTls, 15*time.Second)
		defer f.close()
		writer, reader := f.originPeer, f.clientPeer
		if upload {
			writer, reader = reader, writer
		}
		producerDone := make(chan error, 1)
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range 20 {
				select {
				case <-ticker.C:
					if _, err := writer.Write([]byte{0x5a}); err != nil {
						producerDone <- err
						return
					}
				case <-f.ctx.Done():
					producerDone <- f.ctx.Err()
					return
				}
			}
			producerDone <- nil
		}()
		started := time.Now()
		var payload [1]byte
		for index := range 20 {
			if _, err := io.ReadFull(reader, payload[:]); err != nil {
				<-producerDone
				t.Fatalf("active one-way transfer stopped despite periodic reverse progress: tick=%d elapsed=%s error=%v", index, time.Since(started), err)
			}
		}
		if err := <-producerDone; err != nil {
			t.Fatal(err)
		}
		if time.Since(started) != 100*time.Second || f.ctx.Err() != nil {
			t.Fatalf("virtual active window changed: elapsed=%s canceled=%v", time.Since(started), f.ctx.Err())
		}
		// A real TLS frontend must remain readable after its long quiet side.
		echoDone := make(chan error, 1)
		go func() { _, err := reader.Write([]byte{0x6b}); echoDone <- err }()
		if _, err := io.ReadFull(writer, payload[:]); err != nil {
			t.Fatal(err)
		}
		if err := <-echoDone; err != nil || payload[0] != 0x6b {
			t.Fatalf("opposite direction did not resume: value=%x error=%v", payload[0], err)
		}
	})
}

// A quiet request side must not expire a continuously progressing download.
func TestBidiSharedIdleAllowsActiveDownload(t *testing.T) {
	sharedIdleOneWay(t, false, false)
}

// A quiet response side must not expire a continuously progressing upload.
func TestBidiSharedIdleAllowsActiveUpload(t *testing.T) {
	sharedIdleOneWay(t, true, false)
}

// Avoid transient read-timeout errors on the actual TLS frontend connection.
func TestBidiSharedIdleAllowsActiveTlsFrontend(t *testing.T) {
	sharedIdleOneWay(t, false, true)
}

// Both sides quiet still expire at exactly the configured thirty seconds.
func TestBidiSharedIdleReclaimsBothIdleDirections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSharedIdleRelayFixture(t, false, 15*time.Second)
		defer f.close()
		started := time.Now()
		err := <-f.done
		var timeout net.Error
		if time.Since(started) != 30*time.Second || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("idle timeout contract changed: elapsed=%s error=%v", time.Since(started), err)
		}
	})
}

// Cancellation must join while virtual periodic traffic remains live.
func TestBidiSharedIdleCancellationStopsContinuousTraffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSharedIdleRelayFixture(t, false, 15*time.Second)
		defer f.close()
		producerDone, consumerDone := make(chan struct{}), make(chan struct{})
		var count atomic.Int64
		go func() {
			defer close(producerDone)
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-f.ctx.Done():
					return
				case <-ticker.C:
					if _, err := f.originPeer.Write([]byte{1}); err != nil {
						return
					}
				}
			}
		}()
		go func() {
			defer close(consumerDone)
			var payload [1]byte
			for {
				if _, err := f.clientPeer.Read(payload[:]); err != nil {
					return
				}
				count.Add(1)
			}
		}()
		time.Sleep(92 * time.Second)
		synctest.Wait()
		if count.Load() != 18 || f.ctx.Err() != nil {
			t.Fatalf("active cancellation premise missing: bytes=%d canceled=%v", count.Load(), f.ctx.Err())
		}
		f.cancel()
		<-f.done
		<-producerDone
		<-consumerDone
	})
}

// Exposes deadline methods without Close, and can hold a deadline update until
// cancellation has already poisoned it. Methods retain no caller buffers.
type sharedIdleDeadlineOnly struct {
	conn             net.Conn
	stateLock        sync.Mutex
	read, write      time.Time
	readCalls        int
	writeCalls       int
	gateRead         bool
	gateWrite        bool
	entered, release chan struct{}
	poisoned         chan struct{}
	gateOnce         sync.Once
	poisonOnce       sync.Once
}

// Counts actual attempts, including an illegal post-cancellation read.
func (self *sharedIdleDeadlineOnly) Read(payload []byte) (int, error) {
	self.stateLock.Lock()
	self.readCalls++
	self.stateLock.Unlock()
	return self.conn.Read(payload)
}

// Counts actual attempts, including an illegal post-cancellation write.
func (self *sharedIdleDeadlineOnly) Write(payload []byte) (int, error) {
	self.stateLock.Lock()
	self.writeCalls++
	self.stateLock.Unlock()
	return self.conn.Write(payload)
}

// The arm gate never blocks a cancellation poison.
func (self *sharedIdleDeadlineOnly) SetReadDeadline(deadline time.Time) error {
	if self.gateRead && deadline != aLongTimeAgo {
		self.gateOnce.Do(func() { close(self.entered); <-self.release })
	}
	err := self.conn.SetReadDeadline(deadline)
	self.stateLock.Lock()
	self.read = deadline
	self.stateLock.Unlock()
	if deadline == aLongTimeAgo && self.poisoned != nil {
		self.poisonOnce.Do(func() { close(self.poisoned) })
	}
	return err
}

// Positive write arms can be held while the poison continues independently.
func (self *sharedIdleDeadlineOnly) SetWriteDeadline(deadline time.Time) error {
	if self.gateWrite && deadline != aLongTimeAgo {
		self.gateOnce.Do(func() { close(self.entered); <-self.release })
	}
	err := self.conn.SetWriteDeadline(deadline)
	self.stateLock.Lock()
	self.write = deadline
	self.stateLock.Unlock()
	if deadline == aLongTimeAgo && self.poisoned != nil {
		self.poisonOnce.Do(func() { close(self.poisoned) })
	}
	return err
}

// Deadline poisoning must still join an endpoint that exposes no Close method.
func TestBidiSharedIdleCancellationUnblocksDeadlineOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, ap := net.Pipe()
		b, bp := net.Pipe()
		defer a.Close()
		defer ap.Close()
		defer b.Close()
		defer bp.Close()
		left, right := &sharedIdleDeadlineOnly{conn: a}, &sharedIdleDeadlineOnly{conn: b}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: left, Writer: left}, relayEndpoint{Reader: right, Writer: right},
				relayConfig{Buffers: ownershipBuffers{}, ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Second})
		}()
		synctest.Wait()
		cancel()
		<-done
		if left.read != aLongTimeAgo || right.read != aLongTimeAgo || left.write != aLongTimeAgo || right.write != aLongTimeAgo {
			t.Fatal("deadline-only cancellation did not leave both endpoints poisoned")
		}
	})
}

// Forces a clear/arm to finish after the cancellation callback's poison.
func sharedIdleCancelDuringDeadline(t *testing.T, write bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		a, ap := net.Pipe()
		b, bp := net.Pipe()
		defer a.Close()
		defer ap.Close()
		defer b.Close()
		defer bp.Close()
		held := &sharedIdleDeadlineOnly{conn: b, gateRead: !write, gateWrite: write,
			entered: make(chan struct{}), release: make(chan struct{}), poisoned: make(chan struct{})}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: a, Writer: a}, relayEndpoint{Reader: held, Writer: held},
				relayConfig{Buffers: ownershipBuffers{}, ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Second})
		}()
		var producerDone chan struct{}
		if write {
			producerDone = make(chan struct{})
			go func() { defer close(producerDone); _, _ = ap.Write([]byte{1}) }()
		}
		<-held.entered
		cancel()
		<-held.poisoned
		close(held.release)
		<-done
		if producerDone != nil {
			<-producerDone
		}
		if !write && (held.readCalls != 0 || held.read != aLongTimeAgo) {
			t.Fatalf("cancellation rearmed a read: calls=%d poisoned=%t", held.readCalls, held.read == aLongTimeAgo)
		}
		if write && (held.writeCalls != 0 || held.write != aLongTimeAgo) {
			t.Fatalf("cancellation rearmed a write: calls=%d poisoned=%t", held.writeCalls, held.write == aLongTimeAgo)
		}
	})
}

// An inherited read deadline clear cannot defeat a concurrent cancellation.
func TestBidiSharedIdleCancellationCannotRearmRead(t *testing.T) {
	sharedIdleCancelDuringDeadline(t, false)
}

// A late write-deadline arm cannot turn cancellation into a fifteen-second wait.
func TestBidiSharedIdleCancellationCannotRearmWrite(t *testing.T) {
	sharedIdleCancelDuringDeadline(t, true)
}

// No consumer accepts the copied byte; the unchanged write timeout wins first.
func TestBidiSharedIdlePreservesBlockedWriteTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSharedIdleRelayFixture(t, false, 15*time.Second)
		defer f.close()
		producerDone := make(chan struct{})
		go func() { defer close(producerDone); _, _ = f.originPeer.Write([]byte{1}) }()
		started := time.Now()
		err := <-f.done
		<-producerDone
		var operation *net.OpError
		if time.Since(started) != 15*time.Second || !errors.As(err, &operation) || operation.Op != "write" || !operation.Timeout() {
			t.Fatalf("blocked write timeout changed: elapsed=%s error=%v", time.Since(started), err)
		}
	})
}

// Hold the first idle-cancellation callback while the copies can finish via a
// separate cancel. The relay must join the held callback before returning.
func TestBidiSharedIdleJoinsRunningTimerCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, ap := net.Pipe()
		b, bp := net.Pipe()
		defer a.Close()
		defer ap.Close()
		defer b.Close()
		defer bp.Close()
		ctx, baseCancel := context.WithCancel(t.Context())
		defer baseCancel()
		entered, release := make(chan struct{}), make(chan struct{})
		var first atomic.Bool
		var cancelCount atomic.Int64
		cancel := func() {
			cancelCount.Add(1)
			if first.CompareAndSwap(false, true) {
				close(entered)
				<-release
			}
			baseCancel()
		}
		done := make(chan error, 1)
		go func() {
			done <- relayBidi(ctx, cancel, relayEndpoint{Reader: a, Writer: a}, relayEndpoint{Reader: b, Writer: b},
				relayConfig{Buffers: ownershipBuffers{}, ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Second})
		}()
		<-entered
		baseCancel()
		synctest.Wait()
		select {
		case <-done:
			close(release)
			t.Fatal("relay returned before its running idle callback joined")
		default:
		}
		close(release)
		if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle callback lost timeout cause: %v", err)
		}
		completedCount := cancelCount.Load()
		time.Sleep(90 * time.Second)
		synctest.Wait()
		if cancelCount.Load() != completedCount {
			t.Fatal("idle callback ran or rearmed after relay completion")
		}
	})
}

// HTTP body-copy callers retain their standalone per-read deadline contract.
func TestRelayCopyPreservesStandaloneReadTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source, peer := net.Pipe()
		defer source.Close()
		defer peer.Close()
		done := make(chan error, 1)
		go func() {
			_, err := relayCopy(t.Context(), io.Discard, source, ownershipBuffers{}, 30*time.Second, 15*time.Second, nil)
			done <- err
		}()
		if _, err := peer.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		err := <-done
		var timeout net.Error
		if time.Since(started) != 30*time.Second || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("standalone per-read timeout changed: elapsed=%s error=%v", time.Since(started), err)
		}
	})
}
