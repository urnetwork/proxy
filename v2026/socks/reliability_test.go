package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/connect/v2026"
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

func TestParseReliabilityFileBadJson(t *testing.T) {
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

func TestApplyFileToSettingsExplicitZeroApplied(t *testing.T) {
	// an explicit 0 in the file must be applied (0 = off / pre-fix behavior),
	// distinct from nil (untouched)
	f := &reliabilityFile{
		MaxFlowsPerExit:           intPtr(0),
		SendStallTimeoutMs:        int64Ptr(0),
		BusyProbe:                 boolPtr(false),
		BlackholeReceiveTimeoutMs: int64Ptr(0),
	}
	s := &connect.ReliabilitySettings{
		MaxFlowsPerExit:         32,
		SendStallTimeout:        3 * time.Second,
		BusyProbe:               true,
		BlackholeReceiveTimeout: 20 * time.Second,
		UdpTeardownSignal:       true,
	}
	applyFileToSettings(s, f)
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
	if !s.UdpTeardownSignal {
		t.Error("UdpTeardownSignal = false, want true (nil field untouched)")
	}
}

func TestMergeReliabilitySettingsPreservesBase(t *testing.T) {
	base := &connect.ReliabilitySettings{
		UdpTeardownSignal:       true,
		SendStallTimeout:        3000 * time.Millisecond,
		MaxFlowsPerExit:         16,
		BlackholeReceiveTimeout: 20 * time.Second,
	}
	s, err := mergeReliabilitySettings(base, reliabilityFile{MaxFlowsPerExit: intPtr(64)})
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

// --- control server loopback guard ---

// --- control server endpoints (with a real multi client is impossible here,
// so use the real server with a stub mc via a minimal fake) ---

// fakeMc implements just enough of the mc surface for the control handlers.
type fakeMc struct {
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

func (self *fakeMc) ReliabilitySettings() *connect.ReliabilitySettings {
	if self.settings == nil {
		return &connect.ReliabilitySettings{}
	}
	return self.settings
}
func (self *fakeMc) SetReliabilitySettings(s *connect.ReliabilitySettings) { self.settings = s }
func (self *fakeMc) ReliabilityMetrics() *connect.ReliabilityMetricsSnapshot {
	if self.metrics == nil {
		return &connect.ReliabilityMetricsSnapshot{}
	}
	return self.metrics
}
func (self *fakeMc) ResetReliabilityMetrics()   { self.resets++ }
func (self *fakeMc) Shuffle()                   { self.shuffled = true }
func (self *fakeMc) ProbeAllExits() int         { self.probed++; return 3 }
func (self *fakeMc) Exits() []*connect.ExitInfo { return self.exits }
func (self *fakeMc) DropExit(id connect.Id) bool {
	self.dropped = append(self.dropped, id.String())
	return true
}
func (self *fakeMc) StallExit(id connect.Id, stalled bool) bool {
	self.stalled = append(self.stalled, id.String())
	return true
}
func (self *fakeMc) MigrateExit(id connect.Id) int {
	self.migrated = append(self.migrated, id.String())
	return 5
}
func (self *fakeMc) PacketStats() *connect.PacketStats {
	return &connect.PacketStats{
		RemoteEgressByteCount:    1024,
		RemoteIngressByteCount:   2048,
		RemoteEgressPacketCount:  10,
		RemoteIngressPacketCount: 20,
	}
}

// --- helpers ---

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }
func boolPtr(v bool) *bool    { return &v }
