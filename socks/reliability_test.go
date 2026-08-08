package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// --- reliability file ---

func writeRelFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reliability.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseReliabilityFilePartial(t *testing.T) {
	path := writeRelFile(t, `{
		"maxFlowsPerExit": 32,
		"sendStallTimeoutMs": 5000,
		"busyProbe": true
	}`)
	f, err := parseReliabilityFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.MaxFlowsPerExit == nil || *f.MaxFlowsPerExit != 32 {
		t.Errorf("MaxFlowsPerExit = %v, want 32", f.MaxFlowsPerExit)
	}
	if f.SendStallTimeoutMs == nil || *f.SendStallTimeoutMs != 5000 {
		t.Errorf("SendStallTimeoutMs = %v, want 5000", f.SendStallTimeoutMs)
	}
	if f.BusyProbe == nil || !*f.BusyProbe {
		t.Errorf("BusyProbe = %v, want true", f.BusyProbe)
	}
	// unspecified fields stay nil (untouched), not zero
	if f.UdpTeardownSignal != nil {
		t.Errorf("UdpTeardownSignal = %v, want nil (untouched)", f.UdpTeardownSignal)
	}
	if f.BlackholeReceiveTimeoutMs != nil {
		t.Errorf("BlackholeReceiveTimeoutMs = %v, want nil (untouched)", f.BlackholeReceiveTimeoutMs)
	}
}

func TestParseReliabilityFileBadJSON(t *testing.T) {
	path := writeRelFile(t, `{not json`)
	if _, err := parseReliabilityFile(path); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestParseReliabilityFileMissing(t *testing.T) {
	if _, err := parseReliabilityFile("/nonexistent/reliability.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFileToSettingsExplicitZeroApplied(t *testing.T) {
	// an explicit 0 in the file must be applied (0 = off / pre-fix behavior),
	// distinct from nil (untouched)
	f := &reliabilityFile{
		MaxFlowsPerExit:           intPtr(0),
		SendStallTimeoutMs:        int64Ptr(0),
		BusyProbe:                 boolPtr(false),
		BlackholeReceiveTimeoutMs: int64Ptr(0),
	}
	s, err := fileToSettings(f)
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxFlowsPerExit != 0 {
		t.Errorf("MaxFlowsPerExit = %d, want 0 (explicit zero applied)", s.MaxFlowsPerExit)
	}
	if s.SendStallTimeout != 0 {
		t.Errorf("SendStallTimeout = %v, want 0", s.SendStallTimeout)
	}
	if s.BusyProbe {
		t.Error("BusyProbe = true, want false")
	}
	if s.BlackholeReceiveTimeout != 0 {
		t.Errorf("BlackholeReceiveTimeout = %v, want 0", s.BlackholeReceiveTimeout)
	}
}

func TestApplyFileOverPreservesBase(t *testing.T) {
	base := &connect.ReliabilitySettings{
		UdpTeardownSignal:       true,
		SendStallTimeout:        3000 * time.Millisecond,
		MaxFlowsPerExit:         16,
		BlackholeReceiveTimeout: 20 * time.Second,
	}
	overlay := &reliabilityFile{MaxFlowsPerExit: intPtr(64)}

	merged := settingsToFile(base)
	if err := applyFileOver(merged, overlay); err != nil {
		t.Fatal(err)
	}
	s, err := fileToSettings(merged)
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxFlowsPerExit != 64 {
		t.Errorf("MaxFlowsPerExit = %d, want 64", s.MaxFlowsPerExit)
	}
	if !s.UdpTeardownSignal {
		t.Error("UdpTeardownSignal lost, want true (preserved from base)")
	}
	if s.SendStallTimeout != 3*time.Second {
		t.Errorf("SendStallTimeout = %v, want 3s (preserved)", s.SendStallTimeout)
	}
	if s.BlackholeReceiveTimeout != 20*time.Second {
		t.Errorf("BlackholeReceiveTimeout = %v, want 20s (preserved)", s.BlackholeReceiveTimeout)
	}
}

func TestSettingsToFileRoundTrip(t *testing.T) {
	s := &connect.ReliabilitySettings{
		UdpTeardownSignal:                  true,
		QuicRebindOnExitLoss:               true,
		TcpCollapseMaxHold:                 1500 * time.Millisecond,
		SendStallTimeout:                   3 * time.Second,
		ClusterAffinityFallback:            true,
		ServerNameAffinityBridge:           true,
		SequenceIdleTimeout:                120 * time.Second,
		TcpSequenceIdleTimeout:             600 * time.Second,
		BlackholeReceiveTimeout:            20 * time.Second,
		MaxFlowsPerExit:                    16,
		AffinityStickyPastCap:              true,
		QuarantineGroupFollow:              true,
		GroupFollowWindow:                  45 * time.Second,
		DialFailureRerace:                  true,
		UplinkStalenessGate:                5 * time.Second,
		SoftVerdictDemote:                  true,
		RemovalBudgetCount:                 2,
		RemovalBudgetWindow:                30 * time.Second,
		StandingReserve:                    true,
		EffectiveTierSelection:             true,
		MinBlackholeDestinations:           2,
		BlackholeLoadCorroboration:         8,
		ProviderProbe:                      true,
		ProbeTimeout:                       4 * time.Second,
		ProbeSampleHostCount:               0,
		ProbeSilenceWarnStreak:             2,
		EvaluationPoolMultiple:             2,
		FormationPollTimeout:               200 * time.Millisecond,
		BusyProbe:                          true,
		BusyProbeBudget:                    0,
		SchedulerPauseTolerance:            2 * time.Second,
		SchedulerPauseRecoveryTimeout:      5 * time.Second,
		BlackholeConnectComparativeTimeout: 10 * time.Second,
		HeartbeatInterval:                  60 * time.Second,
	}

	back, err := fileToSettings(settingsToFile(s))
	if err != nil {
		t.Fatal(err)
	}
	// spot-check the ones with interesting conversions
	if back.MaxFlowsPerExit != 16 {
		t.Errorf("MaxFlowsPerExit = %d, want 16", back.MaxFlowsPerExit)
	}
	if back.SendStallTimeout != 3*time.Second {
		t.Errorf("SendStallTimeout = %v, want 3s", back.SendStallTimeout)
	}
	if back.ProbeSampleHostCount != 0 {
		t.Errorf("ProbeSampleHostCount = %d, want 0 (explicit zero survives)", back.ProbeSampleHostCount)
	}
	if !back.BusyProbe {
		t.Error("BusyProbe lost")
	}
	if back.BusyProbeBudget != 0 {
		t.Errorf("BusyProbeBudget = %v, want 0", back.BusyProbeBudget)
	}
	if back.HeartbeatInterval != 60*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 60s", back.HeartbeatInterval)
	}
}

// --- control server loopback guard ---

func TestControlAddrLoopbackGuard(t *testing.T) {
	ok, err := controlAddrIsLoopback("127.0.0.1:9998")
	if err != nil || !ok {
		t.Errorf("127.0.0.1:9998 should be allowed (ok=%v err=%v)", ok, err)
	}
	ok, err = controlAddrIsLoopback("localhost:9998")
	if err != nil || !ok {
		t.Errorf("localhost:9998 should be allowed (ok=%v err=%v)", ok, err)
	}
	ok, err = controlAddrIsLoopback("[::1]:9998")
	if err != nil || !ok {
		t.Errorf("[::1]:9998 should be allowed (ok=%v err=%v)", ok, err)
	}
	ok, err = controlAddrIsLoopback("0.0.0.0:9998")
	if err != nil || ok {
		t.Errorf("0.0.0.0:9998 must be rejected (ok=%v err=%v)", ok, err)
	}
	ok, err = controlAddrIsLoopback("192.168.1.5:9998")
	if err != nil || ok {
		t.Errorf("192.168.1.5:9998 must be rejected (ok=%v err=%v)", ok, err)
	}
	if _, err := controlAddrIsLoopback("not-an-addr"); err == nil {
		t.Error("expected SplitHostPort error for malformed address")
	}
}

// --- control server endpoints (with a real multi client is impossible here,
// so use the real server with a stub mc via a minimal fake) ---

// fakeMC implements just enough of the mc surface for the control handlers.
type fakeMC struct {
	settings *connect.ReliabilitySettings
	metrics  *connect.ReliabilityMetricsSnapshot
	exits    []*connect.ExitInfo
	dropped  []string
	stalled  []string
	migrated []string
	shuffled bool
	probed   int
	resets   int
}

func (f *fakeMC) ReliabilitySettings() *connect.ReliabilitySettings {
	if f.settings == nil {
		return &connect.ReliabilitySettings{}
	}
	return f.settings
}
func (f *fakeMC) SetReliabilitySettings(s *connect.ReliabilitySettings) { f.settings = s }
func (f *fakeMC) ReliabilityMetrics() *connect.ReliabilityMetricsSnapshot {
	if f.metrics == nil {
		return &connect.ReliabilityMetricsSnapshot{}
	}
	return f.metrics
}
func (f *fakeMC) ResetReliabilityMetrics()   { f.resets++ }
func (f *fakeMC) Shuffle()                   { f.shuffled = true }
func (f *fakeMC) ProbeAllExits() int         { f.probed++; return 3 }
func (f *fakeMC) Exits() []*connect.ExitInfo { return f.exits }
func (f *fakeMC) DropExit(id connect.Id) bool {
	f.dropped = append(f.dropped, id.String())
	return true
}
func (f *fakeMC) StallExit(id connect.Id, stalled bool) bool {
	f.stalled = append(f.stalled, id.String())
	return true
}
func (f *fakeMC) MigrateExit(id connect.Id) int {
	f.migrated = append(f.migrated, id.String())
	return 5
}
func (f *fakeMC) PacketStats() *connect.PacketStats {
	return &connect.PacketStats{
		RemoteEgressByteCount:    1024,
		RemoteIngressByteCount:   2048,
		RemoteEgressPacketCount:  10,
		RemoteIngressPacketCount: 20,
	}
}

func TestControlEndpoints(t *testing.T) {
	mc := &fakeMC{}
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

	// GET /settings returns json with current values
	resp, err := http.Get(srv.URL + "/settings")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got["maxFlowsPerExit"] != nil && got["maxFlowsPerExit"].(float64) != 0 {
		t.Errorf("unexpected maxFlowsPerExit: %v", got["maxFlowsPerExit"])
	}

	// PUT /settings partial merge: set maxFlowsPerExit, keep the rest
	req, _ := http.NewRequest("PUT", srv.URL+"/settings", strings.NewReader(`{"maxFlowsPerExit": 64}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /settings status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	if mc.settings == nil || mc.settings.MaxFlowsPerExit != 64 {
		t.Fatalf("settings after PUT = %+v, want MaxFlowsPerExit=64", mc.settings)
	}

	// POST /actions reset-metrics
	resp, err = http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"reset-metrics"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if mc.resets != 1 {
		t.Errorf("resets = %d, want 1", mc.resets)
	}

	// POST /actions shuffle
	resp, _ = http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"shuffle"}`))
	resp.Body.Close()
	if !mc.shuffled {
		t.Error("shuffle not called")
	}

	// POST /actions probe-all
	resp, _ = http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"probe-all"}`))
	resp.Body.Close()
	if mc.probed != 1 {
		t.Errorf("probed = %d, want 1", mc.probed)
	}

	// POST /actions drop with a valid client id
	cid := "019fde39-e690-add0-ac88-e354a0d76d6a"
	resp, _ = http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"drop","clientId":"`+cid+`"}`))
	resp.Body.Close()
	if len(mc.dropped) != 1 || mc.dropped[0] != cid {
		t.Errorf("dropped = %v, want [%s]", mc.dropped, cid)
	}

	// POST /actions drop with missing clientId -> 400
	resp, _ = http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"drop"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("drop w/o clientId status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// POST /actions unknown action -> 400
	resp, _ = http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"bogus"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bogus action status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// GET /metrics returns the snapshot
	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	var m connect.ReliabilityMetricsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// GET /exits returns the table
	resp, err = http.Get(srv.URL + "/exits")
	if err != nil {
		t.Fatal(err)
	}
	var xs []*connect.ExitInfo
	if err := json.NewDecoder(resp.Body).Decode(&xs); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestControlServerRejectsBadMethod(t *testing.T) {
	mc := &fakeMC{}
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

	req, _ := http.NewRequest("DELETE", srv.URL+"/settings", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /settings status = %d, want 405", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestControlRejectsNonLoopbackOrigin pins the CSRF guard: a browser
// cross-origin request (which always sends Origin) must be refused on the
// mutating endpoints, while requests without Origin (curl) and with a
// loopback Origin pass.
func TestControlRejectsNonLoopbackOrigin(t *testing.T) {
	mc := &fakeMC{}
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

	// no Origin -> allowed (curl)
	req, _ := http.NewRequest("PUT", srv.URL+"/settings", strings.NewReader(`{"maxFlowsPerExit": 16}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT without Origin = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// loopback Origin -> allowed
	req, _ = http.NewRequest("POST", srv.URL+"/actions", strings.NewReader(`{"action":"shuffle"}`))
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST with loopback Origin = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// evil cross-origin -> 403 on both mutating endpoints
	for _, tc := range []struct {
		method, path, body string
	}{
		{"PUT", "/settings", `{"maxFlowsPerExit": 32}`},
		{"POST", "/actions", `{"action":"drop","clientId":"019fde39-e690-add0-ac88-e354a0d76d6a"}`},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with evil Origin = %d, want 403", tc.method, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// the evil-origin drop must not have executed
	if len(mc.dropped) != 0 {
		t.Errorf("drop executed despite non-loopback origin: %v", mc.dropped)
	}
}

// TestControlConcurrentSettingsPut exercises the lost-update race fix: two
// PUTs that set different fields concurrently must both survive.
func TestControlConcurrentSettingsPut(t *testing.T) {
	mc := &fakeMC{}
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		req, _ := http.NewRequest("PUT", srv.URL+"/settings", strings.NewReader(`{"maxFlowsPerExit": 64}`))
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		req, _ := http.NewRequest("PUT", srv.URL+"/settings", strings.NewReader(`{"sendStallTimeoutMs": 5000}`))
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-done
	<-done

	if mc.settings == nil {
		t.Fatal("no settings applied")
	}
	if mc.settings.MaxFlowsPerExit != 64 {
		t.Errorf("MaxFlowsPerExit = %d, want 64 (lost update)", mc.settings.MaxFlowsPerExit)
	}
	if mc.settings.SendStallTimeout != 5*time.Second {
		t.Errorf("SendStallTimeout = %v, want 5s (lost update)", mc.settings.SendStallTimeout)
	}
}

// --- helpers ---

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }
func boolPtr(v bool) *bool    { return &v }
