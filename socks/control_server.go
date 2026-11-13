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
var controlPanelHTML []byte

//go:embed ur_logo.svg
var urLogoSVG []byte

// mcControl is the slice of the multi client the control plane uses. The real
// *connect.RemoteUserNatMultiClient satisfies it; tests substitute a fake.
type mcControl interface {
	ReliabilitySettings() *connect.ReliabilitySettings
	SetReliabilitySettings(settings *connect.ReliabilitySettings)
	ReliabilityMetrics() *connect.ReliabilityMetricsSnapshot
	ResetReliabilityMetrics()
	Shuffle()
	ProbeAllExits() int
	Exits() []*connect.ExitInfo
	DropExit(clientId connect.Id) bool
	StallExit(clientId connect.Id, stalled bool) bool
	MigrateExit(clientId connect.Id) int
	PacketStats() *connect.PacketStats
}

// controlServer exposes the live connection to a local http client so the
// dev knobs can be changed mid-run without a reconnect, mirroring the android
// developer screen. Bind it to loopback -- it is an unauthenticated control
// plane. Even on loopback, mutating requests are rejected unless they carry
// no Origin header or a loopback Origin, so a web page open in a browser
// cannot drive the control plane (same class as the webpack-dev-server
// drive-by-localhost CVEs).
type controlServer struct {
	server       *http.Server
	listener     net.Listener
	allowedHosts map[string]bool // Host header values this server answers to
	mc           mcControl
	mu           sync.Mutex         // serializes the read-merge-write of settings
	started      time.Time          // when the control server came up; session elapsed
	cancel       context.CancelFunc // optional: quit action cancels the session ctx
}

// SetCancel wires the session cancel function so the "quit" action can stop
// the process gracefully (same path as Ctrl+C).
func (c *controlServer) SetCancel(cancel context.CancelFunc) {
	c.cancel = cancel
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
	c := &controlServer{
		listener: ln,
		allowedHosts: map[string]bool{
			net.JoinHostPort(tcpAddr.IP.String(), port): true,
			net.JoinHostPort("localhost", port):         true,
		},
		mc:      mc,
		started: time.Now(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.handleRoot)
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(urLogoSVG)
	})
	mux.HandleFunc("/settings", c.handleSettings)
	mux.HandleFunc("/actions", c.handleActions)
	mux.HandleFunc("/metrics", c.handleMetrics)
	mux.HandleFunc("/exits", c.handleExits)
	mux.HandleFunc("/stats", c.handleStats)
	c.server = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           c.requireAllowedHost(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return c, nil
}

// requireAllowedHost answers 403 to any request whose Host header is not one
// of the control server's own addresses. The Origin check covers writes from a
// browser, and this check covers reads, which a DNS rebinding page can make
// with no Origin header at all.
func (c *controlServer) requireAllowedHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.allowedHosts[strings.ToLower(r.Host)] {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not allowed"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *controlServer) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c.server.Shutdown(shutdownCtx)
	}()
	if err := c.server.Serve(c.listener); err != nil && err != http.ErrServerClosed {
		fmt.Printf("control server error: %v\n", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// handleRoot serves the embedded dev panel (the GUI mirror of the android
// developer screen). Everything else on / is a 404; the api routes are
// registered explicitly.
func (c *controlServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(controlPanelHTML)
}

// loopbackOrigin reports whether the request's Origin header (if any) is a
// loopback origin. A request with no Origin header (curl, local scripts) is
// allowed; a browser cross-origin request always sends Origin, and only
// loopback origins may drive the unauthenticated control plane.
func loopbackOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	return true
}

// GET /settings -> current ReliabilitySettings as ms/json
// PUT /settings -> partial reliabilityFile; only named fields change
func (c *controlServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.mu.Lock()
		s := c.mc.ReliabilitySettings()
		c.mu.Unlock()
		writeJSON(w, http.StatusOK, settingsToFile(s))
	case http.MethodPut, http.MethodPost:
		if !loopbackOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "non-loopback origin rejected"})
			return
		}
		var f reliabilityFile
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KiB is plenty for a settings overlay
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// start from current so unset fields are preserved
		c.mu.Lock()
		merged := mergeReliabilitySettings(c.mc.ReliabilitySettings(), f)
		c.mc.SetReliabilitySettings(merged)
		out := settingsToFile(c.mc.ReliabilitySettings())
		c.mu.Unlock()
		writeJSON(w, http.StatusOK, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// POST /actions {"action":"drop|stall|migrate|shuffle|probe-all|reset-metrics","clientId":"...","stalled":true}
func (c *controlServer) handleActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !loopbackOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "non-loopback origin rejected"})
		return
	}
	var req struct {
		Action   string `json:"action"`
		ClientId string `json:"clientId"`
		Stalled  bool   `json:"stalled"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	switch req.Action {
	case "quit":
		if c.cancel != nil {
			c.cancel()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "quitting": true})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no cancel wired"})
		}
	case "reset-metrics":
		c.mc.ResetReliabilityMetrics()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "shuffle":
		c.mc.Shuffle()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "probe-all":
		n := c.mc.ProbeAllExits()
		writeJSON(w, http.StatusOK, map[string]any{"scheduled": n})
	case "drop", "stall", "migrate":
		if req.ClientId == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clientId required"})
			return
		}
		id, err := connect.ParseId(req.ClientId)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("bad clientId: %v", err)})
			return
		}
		switch req.Action {
		case "drop":
			ok := c.mc.DropExit(id)
			writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
		case "stall":
			ok := c.mc.StallExit(id, req.Stalled)
			writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
		case "migrate":
			n := c.mc.MigrateExit(id)
			writeJSON(w, http.StatusOK, map[string]any{"moved": n})
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action"})
	}
}

// GET /metrics -> reliability snapshot
func (c *controlServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := c.mc.ReliabilityMetrics()
	writeJSON(w, http.StatusOK, m)
}

// GET /exits -> current exit table
func (c *controlServer) handleExits(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, c.mc.Exits())
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
func (c *controlServer) handleStats(w http.ResponseWriter, r *http.Request) {
	ps := c.mc.PacketStats()
	elapsed := time.Since(c.started) / time.Second
	writeJSON(w, http.StatusOK, &statsResponse{
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

// mergeReliabilitySettings returns a copy of cur with the fields f names
// overwritten. A field f does not name keeps its current value, including the
// fields the file shape has no entry for.
func mergeReliabilitySettings(cur *connect.ReliabilitySettings, f reliabilityFile) *connect.ReliabilitySettings {
	merged := connect.ReliabilitySettings{}
	if cur != nil {
		merged = *cur
	}
	applyFileToSettings(&merged, &f)
	return &merged
}
