package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// startTestControl binds a control server to an ephemeral loopback port and
// serves it with httptest, so a request's Host matches the bound address.
func startTestControl(t *testing.T, mc mcControl) (*controlServer, *httptest.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := newControlServer(ln, mc)
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(c.server.Handler)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return c, srv
}

func getWithHost(t *testing.T, url string, host string) int {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestControlRefusesForeignHost covers the DNS rebinding read: a page that
// rebinds its own name to 127.0.0.1 sends that name as Host and no Origin.
func TestControlRefusesForeignHost(t *testing.T) {
	_, srv := startTestControl(t, &fakeMC{})
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)

	for _, path := range []string{"/", "/settings", "/metrics", "/exits", "/stats"} {
		for _, host := range []string{
			"rebind.example:" + port,
			"rebind.example",
			"127.0.0.1.rebind.example:" + port,
			"127.0.0.1:" + strconv.Itoa(1+atoiOr(port, 1)),
		} {
			if got := getWithHost(t, srv.URL+path, host); got != http.StatusForbidden {
				t.Errorf("GET %s with Host %q = %d, want 403", path, host, got)
			}
		}
	}
}

func TestControlAnswersItsOwnHost(t *testing.T) {
	_, srv := startTestControl(t, &fakeMC{})
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)

	for _, host := range []string{"", "localhost:" + port, "LOCALHOST:" + port} {
		for _, path := range []string{"/settings", "/metrics", "/exits", "/stats"} {
			if got := getWithHost(t, srv.URL+path, host); got != http.StatusOK {
				t.Errorf("GET %s with Host %q = %d, want 200", path, host, got)
			}
		}
	}
}

func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}

func TestNewControlServerRefusesNonLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind a wildcard address here: %v", err)
	}
	defer ln.Close()
	if _, err := newControlServer(ln, &fakeMC{}); err == nil {
		t.Error("newControlServer accepted a wildcard listener, want an error")
	}
}

func TestListenControlRefusesNonLoopbackBeforeBinding(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.1:9998", "example.com:9998", "no-port"} {
		ln, err := listenControl(addr)
		if err == nil {
			ln.Close()
			t.Errorf("listenControl(%q) succeeded, want an error", addr)
		}
	}
}

// TestListenControlReportsBindFailure covers a control port that is taken:
// the error has to come back so run() stops, and not only get printed.
func TestListenControlReportsBindFailure(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	if ln, err := listenControl(taken.Addr().String()); err == nil {
		ln.Close()
		t.Error("listenControl on a taken port succeeded, want an error")
	}
}

func TestListenControlBindsLoopback(t *testing.T) {
	ln, err := listenControl("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}
