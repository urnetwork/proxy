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

	"github.com/golang-jwt/jwt/v5"
	"github.com/urnetwork/connect/v2026"
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

// syntheticClientId is visibly not a live id. Use it where a test needs a
// fixed id, and connect.NewId() where the value does not matter.
const syntheticClientId = "00000000-0000-4000-8000-000000000001"

func TestExitLabel(t *testing.T) {
	id, err := connect.ParseId(syntheticClientId)
	if err != nil {
		t.Fatal(err)
	}
	if got := exitLabel(id); got != "00000001" {
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
	cid := connect.NewId().String()
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

func TestGetProviderSpecByProviderId(t *testing.T) {
	locs := loadSampleLocations(t)
	cid := connect.NewId().String()
	specs, err := getProviderSpec(locs, "", "", "", cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].ClientId == nil || specs[0].ClientId.String() != cid {
		t.Fatalf("provider-id spec = %+v, want client %s", specs, cid)
	}
}

func TestGetProviderSpecBadProviderId(t *testing.T) {
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
	expectedJwt := "synthetic-header.synthetic-payload.synthetic-signature"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hello" {
			w.WriteHeader(http.StatusOK)
			return
		}
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
		if r.URL.Path == "/hello" {
			w.WriteHeader(http.StatusOK)
			return
		}
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

// --- /stats session readout ---

// --- serve() shutdown on context cancel ---

// --- printReliabilityMetrics output format ---

func TestPrintReliabilityMetrics(t *testing.T) {
	mc := &fakeMc{
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
			{ClientId: mustParseId(t, syntheticClientId), FlowCount: 5, Tier: 1, EffectiveTier: 1, Proven: true},
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

func TestParseMetricsEvery(t *testing.T) {
	for value, want := range map[string]int64{"0": 0, "1": 1, "5000": 5000} {
		got, err := parseMetricsEvery(value)
		if err != nil || got != want {
			t.Errorf("parseMetricsEvery(%q) = %d, %v, want %d", value, got, err, want)
		}
	}
	// 9223372036855 ms wraps time.Duration negative, and time.NewTicker panics
	// on it. 9223372036854 ms is the largest value that fits.
	if got, err := parseMetricsEvery("9223372036854"); err != nil || got != 9223372036854 {
		t.Errorf("parseMetricsEvery(max) = %d, %v, want it accepted", got, err)
	}
	for _, value := range []string{"-1", "abc", "1.5", " 5", "9223372036855", "9223372036854775807"} {
		if got, err := parseMetricsEvery(value); err == nil {
			t.Errorf("parseMetricsEvery(%q) = %d, want an error", value, got)
		}
	}
}
