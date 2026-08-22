package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/urnetwork/connect"
)

// --- pure helpers in main.go ---

func TestFmtDurationMillis(t *testing.T) {
	cases := []struct {
		ms   int64
		want string
	}{
		{0, "0ms"},
		{500, "500ms"},
		{1000, "1.0s"},
		{1500, "1.5s"},
		{65000, "65.0s"},
		{-1, "-"},
	}
	for _, c := range cases {
		if got := fmtDurationMillis(c.ms); got != c.want {
			t.Errorf("fmtDurationMillis(%d) = %q, want %q", c.ms, got, c.want)
		}
	}
}

func TestExitLabel(t *testing.T) {
	id, err := connect.ParseId("019fde39-e690-add0-ac88-e354a0d76d6a")
	if err != nil {
		t.Fatal(err)
	}
	if got := exitLabel(id); got != "a0d76d6a" {
		t.Errorf("exitLabel = %q, want last-8 chars", got)
	}
	// a short id must be returned whole (the len<=8 branch). connect.ParseId
	// only accepts full-length ids, so test the string logic directly.
	if got := exitLabelString("abcd"); got != "abcd" {
		t.Errorf("exitLabelString(short) = %q, want whole id", got)
	}
	if got := exitLabelString("abcdefgh"); got != "abcdefgh" {
		t.Errorf("exitLabelString(8) = %q, want whole id", got)
	}
}

func TestFilterMapSlice(t *testing.T) {
	nums := []int{1, 2, 3, 4}
	evens := filter(nums, func(v int) bool { return v%2 == 0 })
	if len(evens) != 2 || evens[0] != 2 || evens[1] != 4 {
		t.Errorf("filter evens = %v, want [2 4]", evens)
	}
	doubled := mapSlice(nums, func(v int) int { return v * 2 })
	if len(doubled) != 4 || doubled[3] != 8 {
		t.Errorf("mapSlice doubled = %v, want [2 4 6 8]", doubled)
	}
}

// parseByJwtClientId extracts the client_id claim from an (unverified) JWT.
func TestParseByJwtClientId(t *testing.T) {
	cid := "019fde39-e690-add0-ac88-e354a0d76d6a"
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"client_id": cid,
	})
	signed, err := tok.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseByJwtClientId(signed)
	if err != nil {
		t.Fatalf("parseByJwtClientId: %v", err)
	}
	if got.String() != cid {
		t.Errorf("client id = %s, want %s", got.String(), cid)
	}

	// missing client_id claim -> error
	bad := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x"})
	badSigned, err := bad.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseByJwtClientId(badSigned); err == nil {
		t.Error("expected error for JWT without client_id claim")
	}
}

// --- getProviderSpec using the real sample fixture ---

func loadSampleLocations(t *testing.T) *FindLocationsResult {
	t.Helper()
	data, err := os.ReadFile("findLocations.sample.json")
	if err != nil {
		t.Skipf("sample fixture not present: %v", err)
	}
	var res FindLocationsResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return &res
}

func TestGetProviderSpecByCountry(t *testing.T) {
	locs := loadSampleLocations(t)
	specs, err := getProviderSpec(locs, "", "United States", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].LocationId == nil {
		t.Fatalf("country spec = %+v, want 1 spec with LocationId", specs)
	}
}

func TestGetProviderSpecByCityCaseInsensitive(t *testing.T) {
	locs := loadSampleLocations(t)
	specs, err := getProviderSpec(locs, "los angeles", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].LocationId == nil {
		t.Fatalf("city spec = %+v, want 1 spec", specs)
	}
}

func TestGetProviderSpecByProviderID(t *testing.T) {
	locs := loadSampleLocations(t)
	cid := "019fde39-e690-add0-ac88-e354a0d76d6a"
	specs, err := getProviderSpec(locs, "", "", "", cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].ClientId == nil || specs[0].ClientId.String() != cid {
		t.Fatalf("provider-id spec = %+v, want client %s", specs, cid)
	}
}

func TestGetProviderSpecBadProviderID(t *testing.T) {
	locs := loadSampleLocations(t)
	if _, err := getProviderSpec(locs, "", "", "", "not-an-id"); err == nil {
		t.Fatal("expected error for malformed provider id")
	}
}

func TestGetProviderSpecNoMatch(t *testing.T) {
	locs := loadSampleLocations(t)
	if _, err := getProviderSpec(locs, "", "Atlantis", "", ""); err == nil {
		t.Fatal("expected error for unmatched country")
	}
}

// --- loginWithAuthCode against a stubbed /auth/code-login ---

func TestLoginWithAuthCodeSuccess(t *testing.T) {
	expectedJwt := "eyJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOiIwMTlmZGUzOS1lNjkwLWFkZDAtYWM4OC1lMzU0YTBkNzZkNmEifQ.fake"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/code-login" {
			t.Errorf("path = %s, want /auth/code-login", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["auth_code"] != "the-code" {
			t.Errorf("auth_code = %v, want the-code", body["auth_code"])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"by_jwt": expectedJwt})
	}))
	defer srv.Close()

	got, err := loginWithAuthCode(context.Background(), srv.URL, "the-code")
	if err != nil {
		t.Fatalf("loginWithAuthCode: %v", err)
	}
	if got != expectedJwt {
		t.Errorf("jwt = %q, want %q", got, expectedJwt)
	}
}

func TestLoginWithAuthCodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"message": "invalid auth code"},
		})
	}))
	defer srv.Close()

	if _, err := loginWithAuthCode(context.Background(), srv.URL, "bad"); err == nil {
		t.Fatal("expected error for rejected auth code")
	} else if !strings.Contains(err.Error(), "invalid auth code") {
		t.Errorf("error = %v, want it to surface the backend message", err)
	}
}

// --- control server error branches ---

func TestControlSettingsBadJSON(t *testing.T) {
	mc := &fakeMC{}
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

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
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

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
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	c.SetCancel(func() { cancelled = true })
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

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

// --- /stats session readout ---

func TestControlStatsEndpoint(t *testing.T) {
	mc := &fakeMC{}
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.server.Handler)
	defer srv.Close()

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

// --- serve() shutdown on context cancel ---

func TestControlServerServeShutdown(t *testing.T) {
	mc := &fakeMC{}
	// port 0 = ephemeral; we only verify the goroutine exits on ctx cancel
	c, err := newControlServer("127.0.0.1:0", mc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.serve(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// clean exit
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return within 3s of ctx cancel")
	}
}

// --- printReliabilityMetrics output format ---

func TestPrintReliabilityMetrics(t *testing.T) {
	mc := &fakeMC{
		settings: &connect.ReliabilitySettings{},
		metrics: &connect.ReliabilityMetricsSnapshot{
			FlowsOpened:               12,
			DialFailuresIntercepted:   3,
			FlowsReraced:              2,
			ExitLossEvents:            1,
			FlowsLostToExit:           4,
			MaxFlowsLostInOneEvent:    4,
			MeanFlowsLostPerExitLoss:  4.0,
			RecoveryCount:             1,
			RecoveryMeanNanos:         500 * 1e6,
			RecoveryMaxNanos:          1500 * 1e6,
			ProbesSent:                10,
			ProbesAnswered:            8,
			ProvidersQualified:        3,
			VerdictsHeldUplinkStale:   2,
			VerdictsHeldTransportDown: 1,
		},
		exits: []*connect.ExitInfo{
			{ClientId: mustParseId(t, "019fde39-e690-add0-ac88-e354a0d76d6a"), FlowCount: 5, Tier: 1, EffectiveTier: 1, Proven: true},
		},
	}

	// capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printReliabilityMetrics(mc)
	w.Close()
	os.Stdout = old
	buf, _ := io.ReadAll(r)
	r.Close()
	out := string(buf)

	for _, want := range []string{
		"reliability metrics",
		"flows_opened=12",
		"dial_failures_intercepted=3",
		"exit_loss_events=1",
		"mean_flows_lost_per_exit_loss=4.00",
		"recovery_mean=500ms",
		"probes_sent=10",
		"verdicts_held_uplink_stale=2",
		"exits:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q; got:\n%s", want, out)
		}
	}
}

func mustParseId(t *testing.T, s string) connect.Id {
	t.Helper()
	id, err := connect.ParseId(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
