// Exercises request ownership through the real transport with no sockets or
// external services. The bubble joins every transport worker at test completion.
package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect"
)

// Canceling a request must retain its drain ownership until the transport's
// detached authentication and dial callback has actually finished.
func TestHttpProxyDrainRetainsDetachedDial(t *testing.T) {
	// The allocator's process-wide diagnostic loop is unrelated to this request
	// and must be initialized outside the isolated request-worker bubble.
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		requestCtx, cancelRequest := context.WithCancel(ctx)
		defer cancelRequest()
		entered := make(chan struct{})
		release := make(chan struct{})
		callbackDone := make(chan struct{})
		handlerDone := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		proxy := NewHttpProxy(DefaultHttpProxySettings())
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) {
			defer close(callbackDone)
			close(entered)
			<-release
			return nil, errors.New("synthetic detached dial released")
		}
		request := httptest.NewRequestWithContext(requestCtx, http.MethodGet, "http://upstream.example/", nil)
		go func() {
			defer close(handlerDone)
			proxy.ServeHTTP(httptest.NewRecorder(), request)
		}()
		defer func() {
			cancelRequest()
			unblock()
			proxy.Drain()
			joinCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			for _, done := range []<-chan struct{}{callbackDone, handlerDone} {
				select {
				case <-done:
				case <-joinCtx.Done():
					t.Error("released request did not join its callback and handler")
				}
			}
			if !proxy.WaitIdle(joinCtx) {
				t.Error("released request did not become idle")
			}
			synctest.Wait()
		}()
		select {
		case <-entered:
		case <-handlerDone:
			t.Fatal("request did not enter the actual transport dial callback")
		case <-ctx.Done():
			t.Fatal("transport dial callback did not start")
		}
		cancelRequest()
		// Cancellation and all runnable transport/handler work settle here. The
		// held callback is the only release needed for the request to finish.
		synctest.Wait()
		proxy.Drain()
		canceledCtx, stop := context.WithCancel(context.Background())
		stop()
		if proxy.WaitIdle(canceledCtx) {
			t.Errorf("drain certified idle with the actual detached dial callback still held (active=%d)", proxy.ActiveCount())
		}
		if active := proxy.ActiveCount(); active != 1 {
			t.Errorf("held request active count = %d, want 1", active)
		}
	})
}
