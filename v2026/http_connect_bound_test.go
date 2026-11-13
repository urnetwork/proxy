package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// connectStatus sends one CONNECT and reads the proxy's answer, failing the
// test if none arrives within wait. The client stays connected throughout, the
// way the clients that held tens of thousands of retrying CONNECTs open did.
func connectStatus(t *testing.T, proxyAddr string, target string, wait time.Duration) (*http.Response, time.Duration) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	start := time.Now()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	conn.SetReadDeadline(start.Add(wait))
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatalf("CONNECT %s was not answered within %s: %v", target, wait, err)
	}
	response.Body.Close()
	return response, time.Since(start)
}

// A refusal no retry can change is answered at once, with its class's
// status, and dialed exactly once. The retry loop used to retry every error
// class until the client hung up, and to answer nothing before that.
func TestConnectRefusalIsAnsweredWithoutRetry(t *testing.T) {
	classes := map[string]ConnectRefusalClass{
		"unauthenticated.test:443": ConnectRefusalUnauthenticated,
		"forbidden.test:443":       ConnectRefusalForbidden,
		"unknown-proxy.test:443":   ConnectRefusalUnknownProxy,
		"reset.test:25":            ConnectRefusalReset,
		"no-such-host.test:443":    ConnectRefusalNoSuchHost,
	}
	statusCodes := map[string]int{
		"unauthenticated.test:443": http.StatusProxyAuthRequired,
		"forbidden.test:443":       http.StatusForbidden,
		"unknown-proxy.test:443":   http.StatusBadGateway,
		"reset.test:25":            http.StatusBadGateway,
		"no-such-host.test:443":    http.StatusBadGateway,
	}

	var dialLock sync.Mutex
	dials := map[string]int{}
	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
		dialLock.Lock()
		dials[addr] += 1
		dialLock.Unlock()
		return nil, NewConnectRefusal(classes[addr], fmt.Errorf("refused %s", addr))
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	for target, statusCode := range statusCodes {
		response, elapsed := connectStatus(t, proxyAddr, target, 2*time.Second)
		if response.StatusCode != statusCode {
			t.Fatalf("CONNECT %s status = %d, want %d", target, response.StatusCode, statusCode)
		}
		if 500*time.Millisecond < elapsed {
			t.Fatalf("CONNECT %s was answered after %s; a refusal must not wait out a backoff", target, elapsed)
		}
		if statusCode == http.StatusProxyAuthRequired && response.Header.Get("Proxy-Authenticate") == "" {
			t.Fatalf("407 for %s carries no Proxy-Authenticate challenge", target)
		}
	}

	// longer than the first backoff: a retrying loop would have dialed again
	time.Sleep(minProxyConnectTimeout + 500*time.Millisecond)
	dialLock.Lock()
	for target := range statusCodes {
		if dials[target] != 1 {
			t.Errorf("CONNECT %s dialed %d times, want 1: the refusal was retried", target, dials[target])
		}
	}
	dialLock.Unlock()

	stats := proxy.Stats()
	if stats.ConnectDialErrors != 5 || stats.ConnectClientsGone != 0 || stats.ConnectTimeouts != 0 {
		t.Fatalf("stats %+v: want 5 dial errors and no clients gone or timeouts", stats)
	}
	refused := []uint64{
		stats.DialRefusedUnauthenticated,
		stats.DialRefusedForbidden,
		stats.DialRefusedUnknownProxy,
		stats.DialRefusedReset,
		stats.DialRefusedNoSuchHost,
	}
	for class, count := range refused {
		if count != 1 {
			t.Fatalf("refusal class %d counted %d times, want 1: %+v", class+1, count, stats)
		}
	}
}

// serveConnectInBubble serves one CONNECT through the actual handler over a
// pipe inside the caller's synctest bubble, so its backoff runs on the
// bubble's clock. It returns the client end and the handler's completion.
func serveConnectInBubble(proxy *HttpProxy, target string) (net.Conn, <-chan struct{}) {
	client, peer := net.Pipe()
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		proxy.ServeHTTP(
			&httpDialTestHijacker{ResponseRecorder: httptest.NewRecorder(), conn: client},
			httptest.NewRequest(http.MethodConnect, "https://"+target, nil),
		)
	}()
	return peer, handlerDone
}

// A transient failure is retried with a doubling backoff inside the budget,
// then answered 504. The loop used to retry every second until the client
// hung up, and to answer nothing to a client that stayed.
func TestConnectTransientFailureBacksOffThenAnswers504(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		settings := testHttpSettings()
		settings.ProxyConnectTimeout = minProxyConnectTimeout
		settings.ProxyConnectBudget = 3500 * time.Millisecond

		start := time.Now()
		var attemptLock sync.Mutex
		attempts := []time.Duration{}
		proxy := NewHttpProxy(settings)
		proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
			attemptLock.Lock()
			defer attemptLock.Unlock()
			attempts = append(attempts, time.Since(start))
			return nil, errors.New("transient dial failure")
		}
		peer, handlerDone := serveConnectInBubble(proxy, "transient.test:443")
		defer func() {
			peer.Close()
			<-handlerDone
		}()

		peer.SetReadDeadline(start.Add(time.Minute))
		response, err := http.ReadResponse(bufio.NewReader(peer), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("a client that stayed was not answered within a minute: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("status = %d, want 504", response.StatusCode)
		}
		if elapsed := time.Since(start); elapsed != settings.ProxyConnectBudget {
			t.Fatalf("answered after %s, want the %s budget", elapsed, settings.ProxyConnectBudget)
		}

		attemptLock.Lock()
		defer attemptLock.Unlock()
		// 0s, then 1s and 2s backoffs; the next attempt, at 7s, is past the budget
		want := []time.Duration{0, time.Second, 3 * time.Second}
		if !slices.Equal(attempts, want) {
			t.Fatalf("attempts at %v, want %v", attempts, want)
		}
		stats := proxy.Stats()
		if stats.ConnectTimeouts != 1 || stats.ConnectDialErrors != 3 || stats.ConnectClientsGone != 0 {
			t.Fatalf("stats %+v: want 1 timeout, 3 dial errors, no clients gone", stats)
		}
	})
}

// The backoff doubles up to its cap: a 30-second budget holds attempts at
// 0, 1, 3, 7, 15 and 23 seconds and is answered at 30.
func TestConnectBackoffIsCapped(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		settings := testHttpSettings()
		settings.ProxyConnectBudget = 30 * time.Second

		start := time.Now()
		var attemptLock sync.Mutex
		attempts := []time.Duration{}
		proxy := NewHttpProxy(settings)
		proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
			attemptLock.Lock()
			defer attemptLock.Unlock()
			attempts = append(attempts, time.Since(start))
			return nil, errors.New("transient dial failure")
		}
		peer, handlerDone := serveConnectInBubble(proxy, "transient.test:443")
		defer func() {
			peer.Close()
			<-handlerDone
		}()

		peer.SetReadDeadline(start.Add(time.Minute))
		response, err := http.ReadResponse(bufio.NewReader(peer), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("a client that stayed was not answered within a minute: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusGatewayTimeout || time.Since(start) != settings.ProxyConnectBudget {
			t.Fatalf("status %d after %s, want 504 after %s", response.StatusCode, time.Since(start), settings.ProxyConnectBudget)
		}
		attemptLock.Lock()
		defer attemptLock.Unlock()
		want := []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second, 23 * time.Second}
		if !slices.Equal(attempts, want) {
			t.Fatalf("attempts at %v, want %v", attempts, want)
		}
	})
}

// The budget reaches the dial callback as a deadline, so a dial that waits on
// its upstream (a device window that never forms) ends with the budget too.
func TestConnectBudgetBoundsBlockedDial(t *testing.T) {
	connect.MessagePoolCounts()
	synctest.Test(t, func(t *testing.T) {
		settings := testHttpSettings()
		settings.ProxyConnectBudget = 1500 * time.Millisecond

		start := time.Now()
		var dials atomic.Int64
		var sawDeadline atomic.Bool
		proxy := NewHttpProxy(settings)
		proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
			dials.Add(1)
			_, ok := ctx.Deadline()
			sawDeadline.Store(ok)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		peer, handlerDone := serveConnectInBubble(proxy, "blocked.test:443")
		defer func() {
			peer.Close()
			<-handlerDone
		}()

		peer.SetReadDeadline(start.Add(time.Minute))
		response, err := http.ReadResponse(bufio.NewReader(peer), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("a client that stayed was not answered within a minute: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusGatewayTimeout || time.Since(start) != settings.ProxyConnectBudget {
			t.Fatalf("status %d after %s, want 504 after %s", response.StatusCode, time.Since(start), settings.ProxyConnectBudget)
		}
		if !sawDeadline.Load() {
			t.Fatal("the dial callback's context carried no deadline")
		}
		if got := dials.Load(); got != 1 {
			t.Fatalf("%d dials, want 1", got)
		}
	})
}

// Plain http shares the dial callback, so its refusals are answered at once
// too rather than retried for as long as the client waits.
func TestHttpRequestRefusalIsAnsweredWithoutRetry(t *testing.T) {
	var dials atomic.Int64
	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialContextWithRequest = func(ctx context.Context, r *http.Request, network string, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, NewConnectRefusal(ConnectRefusalForbidden, errors.New("Not authorized"))
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	start := time.Now()
	conn.SetDeadline(start.Add(2 * time.Second))
	fmt.Fprintf(conn, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the refused request was not answered: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
	if elapsed := time.Since(start); 500*time.Millisecond < elapsed {
		t.Fatalf("answered after %s; a refusal must not wait out a backoff", elapsed)
	}
	time.Sleep(minProxyConnectTimeout + 500*time.Millisecond)
	if got := dials.Load(); got != 1 {
		t.Fatalf("%d dials, want 1: the refusal was retried", got)
	}
	if got := proxy.Stats().DialRefusedForbidden; got != 1 {
		t.Fatalf("forbidden refusals = %d, want 1", got)
	}
}

// The refusal's status is the class's, and errors.As finds a refusal wrapped
// on its way out of a callback.
func TestConnectRefusalStatusCodes(t *testing.T) {
	want := map[ConnectRefusalClass]int{
		ConnectRefusalUnauthenticated: http.StatusProxyAuthRequired,
		ConnectRefusalForbidden:       http.StatusForbidden,
		ConnectRefusalUnknownProxy:    http.StatusBadGateway,
		ConnectRefusalReset:           http.StatusBadGateway,
		ConnectRefusalNoSuchHost:      http.StatusBadGateway,
	}
	for class, statusCode := range want {
		err := fmt.Errorf("wrapped: %w", NewConnectRefusal(class, errors.New("cause")))
		var refusal *ConnectRefusal
		if !errors.As(err, &refusal) || refusal.StatusCode() != statusCode {
			t.Fatalf("class %d: status %v, want %d", class, refusal, statusCode)
		}
		if !strings.Contains(err.Error(), "cause") {
			t.Fatalf("class %d: error %q lost its cause", class, err)
		}
	}
}
