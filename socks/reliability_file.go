package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/urnetwork/connect"
)

// reliabilityFile mirrors connect.ReliabilitySettings with json-friendly
// fields. Durations are milliseconds (same convention as the android dev
// screen's presets); a nil field is untouched (keeps the current/default
// value), while an explicit zero value is applied.
type reliabilityFile struct {
	UdpTeardownSignal                    *bool  `json:"udpTeardownSignal"`
	QuicRebindOnExitLoss                 *bool  `json:"quicRebindOnExitLoss"`
	TcpCollapseMaxHoldMs                 *int64 `json:"tcpCollapseMaxHoldMs"`
	SendStallTimeoutMs                   *int64 `json:"sendStallTimeoutMs"`
	ClusterAffinityFallback              *bool  `json:"clusterAffinityFallback"`
	ServerNameAffinityBridge             *bool  `json:"serverNameAffinityBridge"`
	SequenceIdleTimeoutMs                *int64 `json:"sequenceIdleTimeoutMs"`
	TcpSequenceIdleTimeoutMs             *int64 `json:"tcpSequenceIdleTimeoutMs"`
	BlackholeReceiveTimeoutMs            *int64 `json:"blackholeReceiveTimeoutMs"`
	MaxFlowsPerExit                      *int   `json:"maxFlowsPerExit"`
	AffinityStickyPastCap                *bool  `json:"affinityStickyPastCap"`
	QuarantineGroupFollow                *bool  `json:"quarantineGroupFollow"`
	GroupFollowWindowMs                  *int64 `json:"groupFollowWindowMs"`
	DialFailureRerace                    *bool  `json:"dialFailureRerace"`
	UplinkStalenessGateMs                *int64 `json:"uplinkStalenessGateMs"`
	SoftVerdictDemote                    *bool  `json:"softVerdictDemote"`
	RemovalBudgetCount                   *int   `json:"removalBudgetCount"`
	RemovalBudgetWindowMs                *int64 `json:"removalBudgetWindowMs"`
	StandingReserve                      *bool  `json:"standingReserve"`
	EffectiveTierSelection               *bool  `json:"effectiveTierSelection"`
	MinBlackholeDestinations             *int   `json:"minBlackholeDestinations"`
	BlackholeLoadCorroboration           *int   `json:"blackholeLoadCorroboration"`
	ProviderProbe                        *bool  `json:"providerProbe"`
	ProbeTimeoutMs                       *int64 `json:"probeTimeoutMs"`
	ProbeSampleHostCount                 *int   `json:"probeSampleHostCount"`
	ProbeSilenceWarnStreak               *int   `json:"probeSilenceWarnStreak"`
	EvaluationPoolMultiple               *int   `json:"evaluationPoolMultiple"`
	FormationPollTimeoutMs               *int64 `json:"formationPollTimeoutMs"`
	BusyProbe                            *bool  `json:"busyProbe"`
	BusyProbeBudgetMs                    *int64 `json:"busyProbeBudgetMs"`
	SchedulerPauseToleranceMs            *int64 `json:"schedulerPauseToleranceMs"`
	SchedulerPauseRecoveryTimeoutMs      *int64 `json:"schedulerPauseRecoveryTimeoutMs"`
	BlackholeConnectComparativeTimeoutMs *int64 `json:"blackholeConnectComparativeTimeoutMs"`
	HeartbeatIntervalMs                  *int64 `json:"heartbeatIntervalMs"`
}

// parseReliabilityFile reads and unmarshals a reliability settings file into
// its json shape. Missing fields stay nil (untouched); an explicit zero value
// is applied. See reliabilityFile.
func parseReliabilityFile(path string) (*reliabilityFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f reliabilityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, nil
}

// loadReliabilitySettingsFile reads a settings file and converts it to a
// connect.ReliabilitySettings. Fields absent from the file are left at their
// zero value here; callers that need to preserve engine defaults must merge
// over the current settings first (see applyFileOver + settingsToFile).
func loadReliabilitySettingsFile(path string) (*connect.ReliabilitySettings, error) {
	f, err := parseReliabilityFile(path)
	if err != nil {
		return nil, err
	}
	return fileToSettings(f)
}

// fileToSettings converts the json shape to a connect.ReliabilitySettings.
// Durations are milliseconds in the file, time.Duration in the struct; nil
// fields map to zero values in the struct.
func fileToSettings(f *reliabilityFile) (*connect.ReliabilitySettings, error) {
	if f == nil {
		return &connect.ReliabilitySettings{}, nil
	}
	settings := &connect.ReliabilitySettings{}
	if f.UdpTeardownSignal != nil {
		settings.UdpTeardownSignal = *f.UdpTeardownSignal
	}
	if f.QuicRebindOnExitLoss != nil {
		settings.QuicRebindOnExitLoss = *f.QuicRebindOnExitLoss
	}
	if f.TcpCollapseMaxHoldMs != nil {
		settings.TcpCollapseMaxHold = time.Duration(*f.TcpCollapseMaxHoldMs) * time.Millisecond
	}
	if f.SendStallTimeoutMs != nil {
		settings.SendStallTimeout = time.Duration(*f.SendStallTimeoutMs) * time.Millisecond
	}
	if f.ClusterAffinityFallback != nil {
		settings.ClusterAffinityFallback = *f.ClusterAffinityFallback
	}
	if f.ServerNameAffinityBridge != nil {
		settings.ServerNameAffinityBridge = *f.ServerNameAffinityBridge
	}
	if f.SequenceIdleTimeoutMs != nil {
		settings.SequenceIdleTimeout = time.Duration(*f.SequenceIdleTimeoutMs) * time.Millisecond
	}
	if f.TcpSequenceIdleTimeoutMs != nil {
		settings.TcpSequenceIdleTimeout = time.Duration(*f.TcpSequenceIdleTimeoutMs) * time.Millisecond
	}
	if f.BlackholeReceiveTimeoutMs != nil {
		settings.BlackholeReceiveTimeout = time.Duration(*f.BlackholeReceiveTimeoutMs) * time.Millisecond
	}
	if f.MaxFlowsPerExit != nil {
		settings.MaxFlowsPerExit = *f.MaxFlowsPerExit
	}
	if f.AffinityStickyPastCap != nil {
		settings.AffinityStickyPastCap = *f.AffinityStickyPastCap
	}
	if f.QuarantineGroupFollow != nil {
		settings.QuarantineGroupFollow = *f.QuarantineGroupFollow
	}
	if f.GroupFollowWindowMs != nil {
		settings.GroupFollowWindow = time.Duration(*f.GroupFollowWindowMs) * time.Millisecond
	}
	if f.DialFailureRerace != nil {
		settings.DialFailureRerace = *f.DialFailureRerace
	}
	if f.UplinkStalenessGateMs != nil {
		settings.UplinkStalenessGate = time.Duration(*f.UplinkStalenessGateMs) * time.Millisecond
	}
	if f.SoftVerdictDemote != nil {
		settings.SoftVerdictDemote = *f.SoftVerdictDemote
	}
	if f.RemovalBudgetCount != nil {
		settings.RemovalBudgetCount = *f.RemovalBudgetCount
	}
	if f.RemovalBudgetWindowMs != nil {
		settings.RemovalBudgetWindow = time.Duration(*f.RemovalBudgetWindowMs) * time.Millisecond
	}
	if f.StandingReserve != nil {
		settings.StandingReserve = *f.StandingReserve
	}
	if f.EffectiveTierSelection != nil {
		settings.EffectiveTierSelection = *f.EffectiveTierSelection
	}
	if f.MinBlackholeDestinations != nil {
		settings.MinBlackholeDestinations = *f.MinBlackholeDestinations
	}
	if f.BlackholeLoadCorroboration != nil {
		settings.BlackholeLoadCorroboration = *f.BlackholeLoadCorroboration
	}
	if f.ProviderProbe != nil {
		settings.ProviderProbe = *f.ProviderProbe
	}
	if f.ProbeTimeoutMs != nil {
		settings.ProbeTimeout = time.Duration(*f.ProbeTimeoutMs) * time.Millisecond
	}
	if f.ProbeSampleHostCount != nil {
		settings.ProbeSampleHostCount = *f.ProbeSampleHostCount
	}
	if f.ProbeSilenceWarnStreak != nil {
		settings.ProbeSilenceWarnStreak = *f.ProbeSilenceWarnStreak
	}
	if f.EvaluationPoolMultiple != nil {
		settings.EvaluationPoolMultiple = *f.EvaluationPoolMultiple
	}
	if f.FormationPollTimeoutMs != nil {
		settings.FormationPollTimeout = time.Duration(*f.FormationPollTimeoutMs) * time.Millisecond
	}
	if f.BusyProbe != nil {
		settings.BusyProbe = *f.BusyProbe
	}
	if f.BusyProbeBudgetMs != nil {
		settings.BusyProbeBudget = time.Duration(*f.BusyProbeBudgetMs) * time.Millisecond
	}
	if f.SchedulerPauseToleranceMs != nil {
		settings.SchedulerPauseTolerance = time.Duration(*f.SchedulerPauseToleranceMs) * time.Millisecond
	}
	if f.SchedulerPauseRecoveryTimeoutMs != nil {
		settings.SchedulerPauseRecoveryTimeout = time.Duration(*f.SchedulerPauseRecoveryTimeoutMs) * time.Millisecond
	}
	if f.BlackholeConnectComparativeTimeoutMs != nil {
		settings.BlackholeConnectComparativeTimeout = time.Duration(*f.BlackholeConnectComparativeTimeoutMs) * time.Millisecond
	}
	if f.HeartbeatIntervalMs != nil {
		settings.HeartbeatInterval = time.Duration(*f.HeartbeatIntervalMs) * time.Millisecond
	}

	return settings, nil
}

// applyFileOver copies every non-nil field of src onto dst (both json shapes).
func applyFileOver(dst, src *reliabilityFile) error {
	if src == nil {
		return nil
	}
	if src.UdpTeardownSignal != nil {
		dst.UdpTeardownSignal = src.UdpTeardownSignal
	}
	if src.QuicRebindOnExitLoss != nil {
		dst.QuicRebindOnExitLoss = src.QuicRebindOnExitLoss
	}
	if src.TcpCollapseMaxHoldMs != nil {
		dst.TcpCollapseMaxHoldMs = src.TcpCollapseMaxHoldMs
	}
	if src.SendStallTimeoutMs != nil {
		dst.SendStallTimeoutMs = src.SendStallTimeoutMs
	}
	if src.ClusterAffinityFallback != nil {
		dst.ClusterAffinityFallback = src.ClusterAffinityFallback
	}
	if src.ServerNameAffinityBridge != nil {
		dst.ServerNameAffinityBridge = src.ServerNameAffinityBridge
	}
	if src.SequenceIdleTimeoutMs != nil {
		dst.SequenceIdleTimeoutMs = src.SequenceIdleTimeoutMs
	}
	if src.TcpSequenceIdleTimeoutMs != nil {
		dst.TcpSequenceIdleTimeoutMs = src.TcpSequenceIdleTimeoutMs
	}
	if src.BlackholeReceiveTimeoutMs != nil {
		dst.BlackholeReceiveTimeoutMs = src.BlackholeReceiveTimeoutMs
	}
	if src.MaxFlowsPerExit != nil {
		dst.MaxFlowsPerExit = src.MaxFlowsPerExit
	}
	if src.AffinityStickyPastCap != nil {
		dst.AffinityStickyPastCap = src.AffinityStickyPastCap
	}
	if src.QuarantineGroupFollow != nil {
		dst.QuarantineGroupFollow = src.QuarantineGroupFollow
	}
	if src.GroupFollowWindowMs != nil {
		dst.GroupFollowWindowMs = src.GroupFollowWindowMs
	}
	if src.DialFailureRerace != nil {
		dst.DialFailureRerace = src.DialFailureRerace
	}
	if src.UplinkStalenessGateMs != nil {
		dst.UplinkStalenessGateMs = src.UplinkStalenessGateMs
	}
	if src.SoftVerdictDemote != nil {
		dst.SoftVerdictDemote = src.SoftVerdictDemote
	}
	if src.RemovalBudgetCount != nil {
		dst.RemovalBudgetCount = src.RemovalBudgetCount
	}
	if src.RemovalBudgetWindowMs != nil {
		dst.RemovalBudgetWindowMs = src.RemovalBudgetWindowMs
	}
	if src.StandingReserve != nil {
		dst.StandingReserve = src.StandingReserve
	}
	if src.EffectiveTierSelection != nil {
		dst.EffectiveTierSelection = src.EffectiveTierSelection
	}
	if src.MinBlackholeDestinations != nil {
		dst.MinBlackholeDestinations = src.MinBlackholeDestinations
	}
	if src.BlackholeLoadCorroboration != nil {
		dst.BlackholeLoadCorroboration = src.BlackholeLoadCorroboration
	}
	if src.ProviderProbe != nil {
		dst.ProviderProbe = src.ProviderProbe
	}
	if src.ProbeTimeoutMs != nil {
		dst.ProbeTimeoutMs = src.ProbeTimeoutMs
	}
	if src.ProbeSampleHostCount != nil {
		dst.ProbeSampleHostCount = src.ProbeSampleHostCount
	}
	if src.ProbeSilenceWarnStreak != nil {
		dst.ProbeSilenceWarnStreak = src.ProbeSilenceWarnStreak
	}
	if src.EvaluationPoolMultiple != nil {
		dst.EvaluationPoolMultiple = src.EvaluationPoolMultiple
	}
	if src.FormationPollTimeoutMs != nil {
		dst.FormationPollTimeoutMs = src.FormationPollTimeoutMs
	}
	if src.BusyProbe != nil {
		dst.BusyProbe = src.BusyProbe
	}
	if src.BusyProbeBudgetMs != nil {
		dst.BusyProbeBudgetMs = src.BusyProbeBudgetMs
	}
	if src.SchedulerPauseToleranceMs != nil {
		dst.SchedulerPauseToleranceMs = src.SchedulerPauseToleranceMs
	}
	if src.SchedulerPauseRecoveryTimeoutMs != nil {
		dst.SchedulerPauseRecoveryTimeoutMs = src.SchedulerPauseRecoveryTimeoutMs
	}
	if src.BlackholeConnectComparativeTimeoutMs != nil {
		dst.BlackholeConnectComparativeTimeoutMs = src.BlackholeConnectComparativeTimeoutMs
	}
	if src.HeartbeatIntervalMs != nil {
		dst.HeartbeatIntervalMs = src.HeartbeatIntervalMs
	}
	return nil
}
