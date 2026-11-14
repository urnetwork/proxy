package main

import (
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/v2026"
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

	merged, err := mergeReliabilitySettings(cur, reliabilityFile{MaxFlowsPerExit: intPtr(64)})
	if err != nil {
		t.Fatal(err)
	}

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

	merged, err := mergeReliabilitySettings(cur, reliabilityFile{
		BusyProbe:          boolPtr(false),
		SendStallTimeoutMs: int64Ptr(0),
		MaxFlowsPerExit:    intPtr(0),
	})
	if err != nil {
		t.Fatal(err)
	}
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
	merged, err := mergeReliabilitySettings(nil, reliabilityFile{SendStallTimeoutMs: int64Ptr(3000)})
	if err != nil {
		t.Fatal(err)
	}
	if merged.SendStallTimeout != 3*time.Second {
		t.Errorf("SendStallTimeout = %v, want 3s", merged.SendStallTimeout)
	}
}

// TestMergeReliabilitySettingsRejectsBadDurations covers millisecond values
// that would wrap time.Duration or go negative. A rejected overlay changes
// nothing, and the error names the field.
func TestMergeReliabilitySettingsRejectsBadDurations(t *testing.T) {
	maxMs := int64(math.MaxInt64 / int64(time.Millisecond))

	for name, f := range map[string]reliabilityFile{
		"negative":       {SendStallTimeoutMs: int64Ptr(-1)},
		"one past max":   {HeartbeatIntervalMs: int64Ptr(maxMs + 1)},
		"max int64":      {ProbeTimeoutMs: int64Ptr(math.MaxInt64)},
		"min int64":      {BusyProbeBudgetMs: int64Ptr(math.MinInt64)},
		"wraps negative": {FormationPollTimeoutMs: int64Ptr(9223372036855)},
	} {
		cur := &connect.ReliabilitySettings{MaxFlowsPerExit: 7}
		merged, err := mergeReliabilitySettings(cur, f)
		if err == nil {
			t.Errorf("%s: merge accepted %+v as %+v", name, f, merged)
			continue
		}
		if merged != nil {
			t.Errorf("%s: merge returned settings with its error", name)
		}
		if cur.MaxFlowsPerExit != 7 {
			t.Errorf("%s: merge changed the current settings", name)
		}
	}

	// the boundary values are accepted
	for _, ms := range []int64{0, 1, maxMs} {
		merged, err := mergeReliabilitySettings(nil, reliabilityFile{SendStallTimeoutMs: int64Ptr(ms)})
		if err != nil {
			t.Errorf("%d ms rejected: %v", ms, err)
			continue
		}
		if merged.SendStallTimeout != time.Duration(ms)*time.Millisecond || merged.SendStallTimeout < 0 {
			t.Errorf("%d ms became %v", ms, merged.SendStallTimeout)
		}
	}
}

// TestReliabilityFileDurationFieldsAreChecked walks the file shape by
// reflection: every field whose name ends in Ms must be refused when it is
// negative, so a duration field added later cannot skip the check.
func TestReliabilityFileDurationFieldsAreChecked(t *testing.T) {
	typ := reflect.TypeOf(reliabilityFile{})
	checked := 0
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !strings.HasSuffix(field.Name, "Ms") {
			continue
		}
		if field.Type != reflect.TypeOf((*int64)(nil)) {
			t.Fatalf("%s ends in Ms but is %s, not *int64", field.Name, field.Type)
		}
		var f reliabilityFile
		bad := int64(-5)
		reflect.ValueOf(&f).Elem().Field(i).Set(reflect.ValueOf(&bad))
		_, err := mergeReliabilitySettings(nil, f)
		if err == nil {
			t.Errorf("%s = -5 was accepted", field.Name)
		} else if !strings.Contains(err.Error(), field.Name) && !strings.Contains(err.Error(), field.Tag.Get("json")) {
			t.Errorf("%s: error %q does not name the field", field.Name, err)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no duration fields found")
	}
}
