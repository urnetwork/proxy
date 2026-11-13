//go:build dev

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/urnetwork/connect"
)

//go:embed control_panel.html
var controlPanelHtml []byte

//go:embed ur_logo.svg
var urLogoSvg []byte

// controlServer exposes the live connection to a local http client so the
// dev knobs can be changed mid-run without a reconnect, mirroring the android
// developer screen. Bind it to loopback -- it is an unauthenticated control
// plane. Even on loopback, mutating requests are rejected unless they carry
// no Origin header or this server's own origin, so a web page open in a browser
// cannot drive the control plane (same class as the webpack-dev-server
// drive-by-localhost CVEs).
type controlServer struct {
	server       *http.Server
	listener     net.Listener
	allowedHosts map[string]bool // Host header values this server answers to
	mc           mcControl
	stateLock    sync.Mutex         // serializes the read-merge-write of settings
	started      time.Time          // when the control server came up; session elapsed
	cancel       context.CancelFunc // optional: quit action cancels the session ctx
}

// SetCancel wires the session cancel function so the "quit" action can stop
// the process gracefully (same path as Ctrl+C).
func (self *controlServer) SetCancel(cancel context.CancelFunc) {
	self.cancel = cancel
}

// newControlServer builds the local http control plane on a listener the
// caller has already bound. It refuses a listener that is not on a loopback
// address. Requests are answered only when their Host header names the
// address the listener is bound to (or localhost on that port), so a page that
// rebinds its own hostname to 127.0.0.1 cannot read the control plane.
func newControlServer(ln net.Listener, mc mcControl) (*controlServer, error) {
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcpAddr.IP.IsLoopback() {
		return nil, fmt.Errorf("control listener %s is not a loopback address", ln.Addr())
	}
	port := strconv.Itoa(tcpAddr.Port)
	self := &controlServer{
		listener: ln,
		allowedHosts: map[string]bool{
			net.JoinHostPort(tcpAddr.IP.String(), port): true,
			net.JoinHostPort("localhost", port):         true,
		},
		mc:      mc,
		started: time.Now(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", self.handleRoot)
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(urLogoSvg)
	})
	mux.HandleFunc("/settings", self.handleSettings)
	mux.HandleFunc("/actions", self.handleActions)
	mux.HandleFunc("/metrics", self.handleMetrics)
	mux.HandleFunc("/exits", self.handleExits)
	mux.HandleFunc("/stats", self.handleStats)
	self.server = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           self.requireAllowedHost(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return self, nil
}

// requireAllowedHost answers 403 to any request whose Host header is not one
// of the control server's own addresses. The Origin check covers writes from a
// browser, and this check covers reads, which a DNS rebinding page can make
// with no Origin header at all.
func (self *controlServer) requireAllowedHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !self.allowedHosts[strings.ToLower(r.Host)] {
			writeJson(w, http.StatusForbidden, map[string]string{"error": "host not allowed"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (self *controlServer) serve(ctx context.Context) {
	// The waiter below must end when Serve returns, whatever the reason.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		self.server.Shutdown(shutdownCtx)
	}()
	if err := self.server.Serve(self.listener); err != nil && err != http.ErrServerClosed {
		fmt.Printf("control server error: %v\n", err)
	}
}

func writeJson(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// handleRoot serves the embedded dev panel (the GUI mirror of the android
// developer screen). Everything else on / is a 404; the api routes are
// registered explicitly.
func (self *controlServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(controlPanelHtml)
}

// sameOrigin reports whether the request's Origin header, if there is one, is
// this control server's own origin. A request with no Origin header (curl,
// local scripts) is allowed. A browser sends Origin on every cross-origin
// write, and only a page served by this server (the panel) has the server's own
// scheme, host and port. A page on another local port, or on localhost with the
// wrong port, is refused even though its host is loopback.
func (self *controlServer) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return self.allowedHosts[strings.ToLower(u.Host)]
}

// GET /settings -> current ReliabilitySettings as ms/json
// PUT /settings -> partial reliabilityFile; only named fields change
func (self *controlServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		self.stateLock.Lock()
		s := self.mc.ReliabilitySettings()
		self.stateLock.Unlock()
		writeJson(w, http.StatusOK, settingsToFile(s))
	case http.MethodPut, http.MethodPost:
		if !self.sameOrigin(r) {
			writeJson(w, http.StatusForbidden, map[string]string{"error": "cross-origin request rejected"})
			return
		}
		var f reliabilityFile
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KiB is plenty for a settings overlay
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			writeJson(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// start from current so unset fields are preserved
		self.stateLock.Lock()
		merged, err := mergeReliabilitySettings(self.mc.ReliabilitySettings(), f)
		if err != nil {
			self.stateLock.Unlock()
			writeJson(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		self.mc.SetReliabilitySettings(merged)
		out := settingsToFile(self.mc.ReliabilitySettings())
		self.stateLock.Unlock()
		writeJson(w, http.StatusOK, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// POST /actions {"action":"drop|stall|migrate|shuffle|probe-all|reset-metrics","clientId":"...","stalled":true}
func (self *controlServer) handleActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !self.sameOrigin(r) {
		writeJson(w, http.StatusForbidden, map[string]string{"error": "cross-origin request rejected"})
		return
	}
	var req struct {
		Action   string `json:"action"`
		ClientId string `json:"clientId"`
		Stalled  bool   `json:"stalled"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJson(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	switch req.Action {
	case "quit":
		if self.cancel != nil {
			self.cancel()
			writeJson(w, http.StatusOK, map[string]any{"ok": true, "quitting": true})
		} else {
			writeJson(w, http.StatusInternalServerError, map[string]string{"error": "no cancel wired"})
		}
	case "reset-metrics":
		self.mc.ResetReliabilityMetrics()
		writeJson(w, http.StatusOK, map[string]any{"ok": true})
	case "shuffle":
		self.mc.Shuffle()
		writeJson(w, http.StatusOK, map[string]any{"ok": true})
	case "probe-all":
		n := self.mc.ProbeAllExits()
		writeJson(w, http.StatusOK, map[string]any{"scheduled": n})
	case "drop", "stall", "migrate":
		if req.ClientId == "" {
			writeJson(w, http.StatusBadRequest, map[string]string{"error": "clientId required"})
			return
		}
		id, err := connect.ParseId(req.ClientId)
		if err != nil {
			writeJson(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("bad clientId: %v", err)})
			return
		}
		switch req.Action {
		case "drop":
			ok := self.mc.DropExit(id)
			writeJson(w, http.StatusOK, map[string]any{"ok": ok})
		case "stall":
			ok := self.mc.StallExit(id, req.Stalled)
			writeJson(w, http.StatusOK, map[string]any{"ok": ok})
		case "migrate":
			n := self.mc.MigrateExit(id)
			writeJson(w, http.StatusOK, map[string]any{"moved": n})
		}
	default:
		writeJson(w, http.StatusBadRequest, map[string]string{"error": "unknown action"})
	}
}

// GET /metrics -> reliability snapshot
func (self *controlServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := self.mc.ReliabilityMetrics()
	writeJson(w, http.StatusOK, m)
}

// GET /exits -> current exit table
func (self *controlServer) handleExits(w http.ResponseWriter, r *http.Request) {
	writeJson(w, http.StatusOK, self.mc.Exits())
}

// statsResponse is the session-level readout the panel's header row shows:
// elapsed time and bytes/packets up and down since the control server
// started. Egress = traffic sent toward the network (up), Ingress = traffic
// received back (down).
type statsResponse struct {
	ElapsedSeconds int64 `json:"elapsedSeconds"`
	BytesUp        int64 `json:"bytesUp"`
	BytesDown      int64 `json:"bytesDown"`
	PacketsUp      int64 `json:"packetsUp"`
	PacketsDown    int64 `json:"packetsDown"`
}

// GET /stats -> session elapsed + traffic counters
func (self *controlServer) handleStats(w http.ResponseWriter, r *http.Request) {
	ps := self.mc.PacketStats()
	elapsed := time.Since(self.started) / time.Second
	writeJson(w, http.StatusOK, &statsResponse{
		ElapsedSeconds: int64(elapsed),
		BytesUp:        int64(ps.RemoteEgressByteCount),
		BytesDown:      int64(ps.RemoteIngressByteCount),
		PacketsUp:      int64(ps.RemoteEgressPacketCount),
		PacketsDown:    int64(ps.RemoteIngressPacketCount),
	})
}

// settingsToFile renders current settings as the json-friendly shape.
func settingsToFile(s *connect.ReliabilitySettings) *reliabilityFile {
	if s == nil {
		return &reliabilityFile{}
	}
	ms := func(d time.Duration) *int64 {
		v := int64(d / time.Millisecond)
		return &v
	}
	b := func(v bool) *bool { return &v }
	i := func(v int) *int { return &v }
	return &reliabilityFile{
		UdpTeardownSignal:                    b(s.UdpTeardownSignal),
		QuicRebindOnExitLoss:                 b(s.QuicRebindOnExitLoss),
		TcpCollapseMaxHoldMs:                 ms(s.TcpCollapseMaxHold),
		SendStallTimeoutMs:                   ms(s.SendStallTimeout),
		ClusterAffinityFallback:              b(s.ClusterAffinityFallback),
		ServerNameAffinityBridge:             b(s.ServerNameAffinityBridge),
		SequenceIdleTimeoutMs:                ms(s.SequenceIdleTimeout),
		TcpSequenceIdleTimeoutMs:             ms(s.TcpSequenceIdleTimeout),
		BlackholeReceiveTimeoutMs:            ms(s.BlackholeReceiveTimeout),
		MaxFlowsPerExit:                      i(s.MaxFlowsPerExit),
		AffinityStickyPastCap:                b(s.AffinityStickyPastCap),
		QuarantineGroupFollow:                b(s.QuarantineGroupFollow),
		GroupFollowWindowMs:                  ms(s.GroupFollowWindow),
		DialFailureRerace:                    b(s.DialFailureRerace),
		UplinkStalenessGateMs:                ms(s.UplinkStalenessGate),
		SoftVerdictDemote:                    b(s.SoftVerdictDemote),
		RemovalBudgetCount:                   i(s.RemovalBudgetCount),
		RemovalBudgetWindowMs:                ms(s.RemovalBudgetWindow),
		StandingReserve:                      b(s.StandingReserve),
		EffectiveTierSelection:               b(s.EffectiveTierSelection),
		MinBlackholeDestinations:             i(s.MinBlackholeDestinations),
		BlackholeLoadCorroboration:           i(s.BlackholeLoadCorroboration),
		ProviderProbe:                        b(s.ProviderProbe),
		ProbeTimeoutMs:                       ms(s.ProbeTimeout),
		ProbeSampleHostCount:                 i(s.ProbeSampleHostCount),
		ProbeSilenceWarnStreak:               i(s.ProbeSilenceWarnStreak),
		EvaluationPoolMultiple:               i(s.EvaluationPoolMultiple),
		FormationPollTimeoutMs:               ms(s.FormationPollTimeout),
		BusyProbe:                            b(s.BusyProbe),
		BusyProbeBudgetMs:                    ms(s.BusyProbeBudget),
		SchedulerPauseToleranceMs:            ms(s.SchedulerPauseTolerance),
		SchedulerPauseRecoveryTimeoutMs:      ms(s.SchedulerPauseRecoveryTimeout),
		BlackholeConnectComparativeTimeoutMs: ms(s.BlackholeConnectComparativeTimeout),
		HeartbeatIntervalMs:                  ms(s.HeartbeatInterval),
	}
}

// controlAddrIsLoopback reports whether addr is a loopback bind address
// (localhost, 127.0.0.1, or ::1) with a port. The control server is
// unauthenticated, so anything else must be refused.
func controlAddrIsLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false, nil
	}
	return true, nil
}

// listenControl binds the control address before anything else starts, so a
// port that is taken stops the proxy with an error. The control server is
// unauthenticated and can change settings, drop exits and migrate flows, so a
// non-loopback address is refused before it is bound, and newControlServer
// checks the bound address again because a name such as localhost can resolve
// to something else.
func listenControl(addr string) (net.Listener, error) {
	ok, err := controlAddrIsLoopback(addr)
	if err != nil {
		return nil, fmt.Errorf("control address: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("control address %q must be loopback; the control server is unauthenticated", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("control server: %w", err)
	}
	return ln, nil
}

// controlUsage is the --control line of the usage text. Only a dev build has it.
const controlUsage = `
    --control=<addr>               local control http server, dev builds only (env CONTROL, e.g. 127.0.0.1:9998, empty = off)`

// controlFlag reads the control address from --control or CONTROL.
func controlFlag(pick func(optName string, envName string, def string) string) string {
	return pick("--control", "CONTROL", "")
}

// startControl binds the control address, then serves the control plane until
// ctx ends. A failed bind or a non-loopback address is returned.
func startControl(ctx context.Context, stop context.CancelFunc, addr string, mc mcControl) error {
	ln, err := listenControl(addr)
	if err != nil {
		return err
	}
	server, err := newControlServer(ln, mc)
	if err != nil {
		ln.Close()
		return fmt.Errorf("control server: %w", err)
	}
	server.SetCancel(stop)
	go server.serve(ctx)
	fmt.Printf("control server listening on %s\n", ln.Addr())
	return nil
}
