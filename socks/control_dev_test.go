//go:build dev

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

func TestControlSettingsBadJSON(t *testing.T) {
	mc := &fakeMC{}
	_, srv := startTestControl(t, mc)

	req, _ := http.NewRequest("PUT", srv.URL+"/settings", strings.NewReader("{not json"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT bad json status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestControlActionsStallMigrate(t *testing.T) {
	mc := &fakeMC{}
	_, srv := startTestControl(t, mc)

	cid := "019fde39-e690-add0-ac88-e354a0d76d6a"

	resp, err := http.Post(srv.URL+"/actions", "application/json",
		strings.NewReader(`{"action":"stall","clientId":"`+cid+`","stalled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(mc.stalled) != 1 || mc.stalled[0] != cid {
		t.Errorf("stalled = %v, want [%s]", mc.stalled, cid)
	}

	resp, err = http.Post(srv.URL+"/actions", "application/json",
		strings.NewReader(`{"action":"migrate","clientId":"`+cid+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(mc.migrated) != 1 || mc.migrated[0] != cid {
		t.Errorf("migrated = %v, want [%s]", mc.migrated, cid)
	}

	// malformed client id -> 400
	resp, err = http.Post(srv.URL+"/actions", "application/json",
		strings.NewReader(`{"action":"drop","clientId":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("drop bad clientId status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestControlQuitAction verifies the quit action invokes the wired cancel.
func TestControlQuitAction(t *testing.T) {
	mc := &fakeMC{}
	c, srv := startTestControl(t, mc)
	cancelled := false
	c.SetCancel(func() { cancelled = true })

	resp, err := http.Post(srv.URL+"/actions", "application/json", strings.NewReader(`{"action":"quit"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST quit status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	if !cancelled {
		t.Error("quit action did not invoke the session cancel")
	}
}

func TestControlStatsEndpoint(t *testing.T) {
	mc := &fakeMC{}
	_, srv := startTestControl(t, mc)

	resp, err := http.Get(srv.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stats status = %d, want 200", resp.StatusCode)
	}
	var st statsResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.BytesUp != 1024 || st.BytesDown != 2048 {
		t.Errorf("stats bytes = %d up / %d down, want 1024/2048", st.BytesUp, st.BytesDown)
	}
	if st.PacketsUp != 10 || st.PacketsDown != 20 {
		t.Errorf("stats packets = %d up / %d down, want 10/20", st.PacketsUp, st.PacketsDown)
	}
	if st.ElapsedSeconds < 0 {
		t.Errorf("elapsedSeconds = %d, want >= 0", st.ElapsedSeconds)
	}
}

func TestControlServerServeShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := newControlServer(ln, &fakeMC{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.serve(ctx)
		close(done)
	}()

	// A completed request shows the serve loop is up, so no sleep is needed.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cancel()
	select {
	case <-done:
		// clean exit
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return within 3s of ctx cancel")
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

	back := &connect.ReliabilitySettings{}
	applyFileToSettings(back, settingsToFile(s))
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

func TestControlEndpoints(t *testing.T) {
	mc := &fakeMC{}
	_, srv := startTestControl(t, mc)

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
	_, srv := startTestControl(t, mc)

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
	_, srv := startTestControl(t, mc)

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
	_, srv := startTestControl(t, mc)

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

// TestControlPutSettingsKeepsUnnamedFields drives a one-field PUT /settings
// through the control server and checks that the multi client's settings keep
// every other field.
func TestControlPutSettingsKeepsUnnamedFields(t *testing.T) {
	cur := &connect.ReliabilitySettings{}
	fillReliabilitySettings(t, cur)
	before := *cur
	mc := &fakeMC{settings: cur}
	_, srv := startTestControl(t, mc)

	req, _ := http.NewRequest("PUT", srv.URL+"/settings", strings.NewReader(`{"maxFlowsPerExit": 64}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}

	want := before
	want.MaxFlowsPerExit = 64
	if *mc.settings != want {
		t.Errorf("settings after PUT = %+v, want %+v", *mc.settings, want)
	}
}
