package main

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// fillReliabilitySettings sets every field of s to a distinct non-zero value.
// It walks the fields by reflection, so a field that connect adds later is
// covered without a test change. A field of a kind this helper does not know
// fails the test, which is the prompt to extend it.
func fillReliabilitySettings(t *testing.T, s *connect.ReliabilitySettings) {
	t.Helper()
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := v.Type().Field(i).Name
		switch {
		case field.Type() == reflect.TypeOf(time.Duration(0)):
			// whole milliseconds, because the file shape stores milliseconds
			field.SetInt(int64(time.Duration(1000+i) * time.Millisecond))
			continue
		}
		switch field.Kind() {
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Int, reflect.Int32, reflect.Int64:
			field.SetInt(int64(1000 + i))
		case reflect.Float32, reflect.Float64:
			field.SetFloat(0.5 + float64(i))
		default:
			t.Fatalf("ReliabilitySettings.%s has kind %s, which fillReliabilitySettings does not set", name, field.Kind())
		}
	}
}

// TestMergeReliabilitySettingsKeepsEveryUnnamedField checks that a partial
// overlay changes only the field it names. reliabilityFile carries fewer
// fields than connect.ReliabilitySettings, so a merge that rebuilds the struct
// from the file shape would reset the rest to zero.
func TestMergeReliabilitySettingsKeepsEveryUnnamedField(t *testing.T) {
	cur := &connect.ReliabilitySettings{}
	fillReliabilitySettings(t, cur)
	before := *cur

	merged := mergeReliabilitySettings(cur, reliabilityFile{MaxFlowsPerExit: intPtr(64)})

	got := reflect.ValueOf(*merged)
	want := reflect.ValueOf(before)
	for i := 0; i < got.NumField(); i++ {
		name := got.Type().Field(i).Name
		if name == "MaxFlowsPerExit" {
			if merged.MaxFlowsPerExit != 64 {
				t.Errorf("MaxFlowsPerExit = %d, want 64", merged.MaxFlowsPerExit)
			}
			continue
		}
		if !reflect.DeepEqual(got.Field(i).Interface(), want.Field(i).Interface()) {
			t.Errorf("%s = %v, want %v (unnamed field changed)", name, got.Field(i).Interface(), want.Field(i).Interface())
		}
	}
	if *cur != before {
		t.Error("merge changed the current settings it was given")
	}
}

// TestMergeReliabilitySettingsAppliesExplicitZero checks that a named field
// set to zero or false is applied, and that nothing else moves.
func TestMergeReliabilitySettingsAppliesExplicitZero(t *testing.T) {
	cur := &connect.ReliabilitySettings{}
	fillReliabilitySettings(t, cur)

	merged := mergeReliabilitySettings(cur, reliabilityFile{
		BusyProbe:          boolPtr(false),
		SendStallTimeoutMs: int64Ptr(0),
		MaxFlowsPerExit:    intPtr(0),
	})
	if merged.BusyProbe {
		t.Error("BusyProbe = true, want false (explicit false applied)")
	}
	if merged.SendStallTimeout != 0 {
		t.Errorf("SendStallTimeout = %v, want 0", merged.SendStallTimeout)
	}
	if merged.MaxFlowsPerExit != 0 {
		t.Errorf("MaxFlowsPerExit = %d, want 0", merged.MaxFlowsPerExit)
	}
	if !merged.LightClassifier || merged.PlacementHysteresisPct == 0 {
		t.Error("fields the file shape does not carry were reset")
	}
}

// TestMergeReliabilitySettingsNilCurrent checks that a nil current settings
// is treated as empty, and that durations convert from milliseconds.
func TestMergeReliabilitySettingsNilCurrent(t *testing.T) {
	merged := mergeReliabilitySettings(nil, reliabilityFile{SendStallTimeoutMs: int64Ptr(3000)})
	if merged.SendStallTimeout != 3*time.Second {
		t.Errorf("SendStallTimeout = %v, want 3s", merged.SendStallTimeout)
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
