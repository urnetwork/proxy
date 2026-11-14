package main

import (
	"testing"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// TestApplyFileToSettingsAllFields walks every field branch of
// applyFileToSettings by applying a file with every field set onto an empty
// base, then verifying each landed. This is the branch-coverage companion to
// the partial-merge tests.
func TestApplyFileToSettingsAllFields(t *testing.T) {
	overlay := &reliabilityFile{
		UdpTeardownSignal:                    boolPtr(true),
		QuicRebindOnExitLoss:                 boolPtr(true),
		TcpCollapseMaxHoldMs:                 int64Ptr(1500),
		SendStallTimeoutMs:                   int64Ptr(3000),
		ClusterAffinityFallback:              boolPtr(true),
		ServerNameAffinityBridge:             boolPtr(true),
		SequenceIdleTimeoutMs:                int64Ptr(120000),
		TcpSequenceIdleTimeoutMs:             int64Ptr(600000),
		BlackholeReceiveTimeoutMs:            int64Ptr(20000),
		MaxFlowsPerExit:                      intPtr(16),
		AffinityStickyPastCap:                boolPtr(true),
		QuarantineGroupFollow:                boolPtr(true),
		GroupFollowWindowMs:                  int64Ptr(45000),
		DialFailureRerace:                    boolPtr(true),
		UplinkStalenessGateMs:                int64Ptr(5000),
		SoftVerdictDemote:                    boolPtr(true),
		RemovalBudgetCount:                   intPtr(2),
		RemovalBudgetWindowMs:                int64Ptr(30000),
		StandingReserve:                      boolPtr(true),
		EffectiveTierSelection:               boolPtr(true),
		MinBlackholeDestinations:             intPtr(2),
		BlackholeLoadCorroboration:           intPtr(8),
		ProviderProbe:                        boolPtr(true),
		ProbeTimeoutMs:                       int64Ptr(4000),
		ProbeSampleHostCount:                 intPtr(4),
		ProbeSilenceWarnStreak:               intPtr(2),
		EvaluationPoolMultiple:               intPtr(2),
		FormationPollTimeoutMs:               int64Ptr(200),
		BusyProbe:                            boolPtr(true),
		BusyProbeBudgetMs:                    int64Ptr(1500),
		SchedulerPauseToleranceMs:            int64Ptr(2000),
		SchedulerPauseRecoveryTimeoutMs:      int64Ptr(5000),
		BlackholeConnectComparativeTimeoutMs: int64Ptr(10000),
		HeartbeatIntervalMs:                  int64Ptr(60000),
	}

	s := &connect.ReliabilitySettings{}
	applyFileToSettings(s, overlay)

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"UdpTeardownSignal", s.UdpTeardownSignal, true},
		{"QuicRebindOnExitLoss", s.QuicRebindOnExitLoss, true},
		{"TcpCollapseMaxHold", s.TcpCollapseMaxHold, 1500 * time.Millisecond},
		{"SendStallTimeout", s.SendStallTimeout, 3 * time.Second},
		{"ClusterAffinityFallback", s.ClusterAffinityFallback, true},
		{"ServerNameAffinityBridge", s.ServerNameAffinityBridge, true},
		{"SequenceIdleTimeout", s.SequenceIdleTimeout, 120 * time.Second},
		{"TcpSequenceIdleTimeout", s.TcpSequenceIdleTimeout, 600 * time.Second},
		{"BlackholeReceiveTimeout", s.BlackholeReceiveTimeout, 20 * time.Second},
		{"MaxFlowsPerExit", s.MaxFlowsPerExit, 16},
		{"AffinityStickyPastCap", s.AffinityStickyPastCap, true},
		{"QuarantineGroupFollow", s.QuarantineGroupFollow, true},
		{"GroupFollowWindow", s.GroupFollowWindow, 45 * time.Second},
		{"DialFailureRerace", s.DialFailureRerace, true},
		{"UplinkStalenessGate", s.UplinkStalenessGate, 5 * time.Second},
		{"SoftVerdictDemote", s.SoftVerdictDemote, true},
		{"RemovalBudgetCount", s.RemovalBudgetCount, 2},
		{"RemovalBudgetWindow", s.RemovalBudgetWindow, 30 * time.Second},
		{"StandingReserve", s.StandingReserve, true},
		{"EffectiveTierSelection", s.EffectiveTierSelection, true},
		{"MinBlackholeDestinations", s.MinBlackholeDestinations, 2},
		{"BlackholeLoadCorroboration", s.BlackholeLoadCorroboration, 8},
		{"ProviderProbe", s.ProviderProbe, true},
		{"ProbeTimeout", s.ProbeTimeout, 4 * time.Second},
		{"ProbeSampleHostCount", s.ProbeSampleHostCount, 4},
		{"ProbeSilenceWarnStreak", s.ProbeSilenceWarnStreak, 2},
		{"EvaluationPoolMultiple", s.EvaluationPoolMultiple, 2},
		{"FormationPollTimeout", s.FormationPollTimeout, 200 * time.Millisecond},
		{"BusyProbe", s.BusyProbe, true},
		{"BusyProbeBudget", s.BusyProbeBudget, 1500 * time.Millisecond},
		{"SchedulerPauseTolerance", s.SchedulerPauseTolerance, 2 * time.Second},
		{"SchedulerPauseRecoveryTimeout", s.SchedulerPauseRecoveryTimeout, 5 * time.Second},
		{"BlackholeConnectComparativeTimeout", s.BlackholeConnectComparativeTimeout, 10 * time.Second},
		{"HeartbeatInterval", s.HeartbeatInterval, 60 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
