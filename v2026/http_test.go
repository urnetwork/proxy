package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHttpProxyForwardsRequestMetadataAndBody(t *testing.T) {
	type receivedRequest struct {
		host               string
		authorization      string
		contentType        string
		proxyAuthorization string
		body               string
	}

	received := make(chan receivedRequest, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("backend read body: %v", err)
			return
		}
		received <- receivedRequest{
			host:               r.Host,
			authorization:      r.Header.Get("Authorization"),
			contentType:        r.Header.Get("Content-Type"),
			proxyAuthorization: r.Header.Get("Proxy-Authorization"),
			body:               string(body),
		}
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer backend.Close()

	proxy := NewHttpProxy()
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(r.Context(), network, addr)
	}

	req := httptest.NewRequest(http.MethodPost, backend.URL+"/resource", strings.NewReader("request-body"))
	req.Host = "forwarded.example"
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Proxy-Authorization", "proxy-secret")

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, http.StatusCreated, rr.Body.String())
	}
	if rr.Header().Get("X-Backend") != "ok" {
		t.Fatalf("missing backend response header")
	}

	got := <-received
	if got.host != "forwarded.example" {
		t.Fatalf("host = %q, want forwarded.example", got.host)
	}
	if got.authorization != "Bearer token" {
		t.Fatalf("authorization = %q", got.authorization)
	}
	if got.contentType != "text/plain" {
		t.Fatalf("content-type = %q", got.contentType)
	}
	if got.proxyAuthorization != "" {
		t.Fatalf("proxy authorization was forwarded: %q", got.proxyAuthorization)
	}
	if got.body != "request-body" {
		t.Fatalf("body = %q", got.body)
	}
}

func TestHttpProxyRejectsOversizedRequestBody(t *testing.T) {
	proxy := NewHttpProxy()
	proxy.MaxHttpBodyBytes = 3
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		t.Fatalf("dial should not be called for oversized request")
		return nil, context.Canceled
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("four"))
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestHttpProxyConnectTunnel(t *testing.T) {
	backendAddr := startTCPBackend(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("backend read: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("backend got %q, want ping", string(buf))
			return
		}
		_, _ = conn.Write([]byte("pong"))
	})

	proxy := NewHttpProxy()
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(r.Context(), "tcp", backendAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := freeTCPAddr(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ListenAndServe(ctx, "tcp", proxyAddr)
	}()
	waitForTCP(t, proxyAddr)
	defer func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				t.Fatalf("http proxy returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("http proxy did not stop")
		}
	}()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := io.WriteString(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write connect request: %v", err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read connect status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("connect status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read connect headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("tunnel got %q, want pong", string(buf))
	}
}
