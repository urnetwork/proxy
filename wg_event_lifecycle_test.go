// Pins ownership of the tun event channel and the device reader it releases.
package proxy

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/urnetwork/connect"
	uwgtun "github.com/urnetwork/userwireguard/tun"
)

// The real userspace device starts an event reader at construction. Its owner
// must close the channel on shutdown so the bubble has no retained goroutine.
func TestWgCloseReleasesNativeEventReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		settings := DefaultWgProxySettings()
		settings.Log = connect.NewNoopLogger()
		wg := NewWgProxy(t.Context(), settings)
		defer wg.Close()
		synctest.Wait()
		if err := wg.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case _, open := <-wg.Events():
			if open {
				t.Error("tun retained its event channel after native device shutdown")
			}
		default:
			t.Error("native device shutdown left its event reader waiting")
		}
		wg.AddEvent(uwgtun.EventUp)
	})
}

// A full event buffer holds each sender in its actual admission select. Tun
// close cancels them before closing the channel, and repeated closes are safe.
func TestWgTunCloseCancelsConcurrentEventAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		wg := &WgProxy{ctx: ctx, cancel: cancel, events: make(chan uwgtun.Event, 1)}
		tun := &wgTunDevice{proxy: wg}
		wg.AddEvent(uwgtun.EventMTUUpdate)
		const senderCount = 32
		finished := make(chan struct{}, senderCount)
		for range senderCount {
			go func() {
				wg.AddEvent(uwgtun.EventUp)
				finished <- struct{}{}
			}()
		}
		synctest.Wait()
		if len(finished) != 0 {
			t.Error("fixture did not hold the concurrent event senders")
		}
		closed := make(chan error, 2)
		for range 2 {
			go func() { closed <- tun.Close() }()
		}
		for range 2 {
			if err := <-closed; err != nil {
				t.Error(err)
			}
		}
		for range senderCount {
			<-finished
		}
		if event, open := <-wg.Events(); !open || event != uwgtun.EventMTUUpdate {
			t.Fatal("close discarded the already-admitted event")
		}
		select {
		case _, open := <-wg.Events():
			if open {
				t.Error("canceled sender admitted a new event during close")
			}
		default:
			t.Error("tun close did not finish its event channel")
		}
		for range senderCount {
			go func() { wg.AddEvent(uwgtun.EventDown) }()
		}
		synctest.Wait()
	})
}
