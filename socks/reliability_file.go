package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
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

// applyFileToSettings writes every non-nil field of f onto dst. Durations are
// milliseconds in the file and time.Duration in the struct. A nil field leaves
// dst untouched and an explicit zero is applied. Fields of dst that the file
// shape has no entry for are never touched.
func applyFileToSettings(dst *connect.ReliabilitySettings, f *reliabilityFile) {
	if f == nil {
		return
	}
	if f.UdpTeardownSignal != nil {
		dst.UdpTeardownSignal = *f.UdpTeardownSignal
	}
	if f.QuicRebindOnExitLoss != nil {
		dst.QuicRebindOnExitLoss = *f.QuicRebindOnExitLoss
	}
	if f.TcpCollapseMaxHoldMs != nil {
		dst.TcpCollapseMaxHold = time.Duration(*f.TcpCollapseMaxHoldMs) * time.Millisecond
	}
	if f.SendStallTimeoutMs != nil {
		dst.SendStallTimeout = time.Duration(*f.SendStallTimeoutMs) * time.Millisecond
	}
	if f.ClusterAffinityFallback != nil {
		dst.ClusterAffinityFallback = *f.ClusterAffinityFallback
	}
	if f.ServerNameAffinityBridge != nil {
		dst.ServerNameAffinityBridge = *f.ServerNameAffinityBridge
	}
	if f.SequenceIdleTimeoutMs != nil {
		dst.SequenceIdleTimeout = time.Duration(*f.SequenceIdleTimeoutMs) * time.Millisecond
	}
	if f.TcpSequenceIdleTimeoutMs != nil {
		dst.TcpSequenceIdleTimeout = time.Duration(*f.TcpSequenceIdleTimeoutMs) * time.Millisecond
	}
	if f.BlackholeReceiveTimeoutMs != nil {
		dst.BlackholeReceiveTimeout = time.Duration(*f.BlackholeReceiveTimeoutMs) * time.Millisecond
	}
	if f.MaxFlowsPerExit != nil {
		dst.MaxFlowsPerExit = *f.MaxFlowsPerExit
	}
	if f.AffinityStickyPastCap != nil {
		dst.AffinityStickyPastCap = *f.AffinityStickyPastCap
	}
	if f.QuarantineGroupFollow != nil {
		dst.QuarantineGroupFollow = *f.QuarantineGroupFollow
	}
	if f.GroupFollowWindowMs != nil {
		dst.GroupFollowWindow = time.Duration(*f.GroupFollowWindowMs) * time.Millisecond
	}
	if f.DialFailureRerace != nil {
		dst.DialFailureRerace = *f.DialFailureRerace
	}
	if f.UplinkStalenessGateMs != nil {
		dst.UplinkStalenessGate = time.Duration(*f.UplinkStalenessGateMs) * time.Millisecond
	}
	if f.SoftVerdictDemote != nil {
		dst.SoftVerdictDemote = *f.SoftVerdictDemote
	}
	if f.RemovalBudgetCount != nil {
		dst.RemovalBudgetCount = *f.RemovalBudgetCount
	}
	if f.RemovalBudgetWindowMs != nil {
		dst.RemovalBudgetWindow = time.Duration(*f.RemovalBudgetWindowMs) * time.Millisecond
	}
	if f.StandingReserve != nil {
		dst.StandingReserve = *f.StandingReserve
	}
	if f.EffectiveTierSelection != nil {
		dst.EffectiveTierSelection = *f.EffectiveTierSelection
	}
	if f.MinBlackholeDestinations != nil {
		dst.MinBlackholeDestinations = *f.MinBlackholeDestinations
	}
	if f.BlackholeLoadCorroboration != nil {
		dst.BlackholeLoadCorroboration = *f.BlackholeLoadCorroboration
	}
	if f.ProviderProbe != nil {
		dst.ProviderProbe = *f.ProviderProbe
	}
	if f.ProbeTimeoutMs != nil {
		dst.ProbeTimeout = time.Duration(*f.ProbeTimeoutMs) * time.Millisecond
	}
	if f.ProbeSampleHostCount != nil {
		dst.ProbeSampleHostCount = *f.ProbeSampleHostCount
	}
	if f.ProbeSilenceWarnStreak != nil {
		dst.ProbeSilenceWarnStreak = *f.ProbeSilenceWarnStreak
	}
	if f.EvaluationPoolMultiple != nil {
		dst.EvaluationPoolMultiple = *f.EvaluationPoolMultiple
	}
	if f.FormationPollTimeoutMs != nil {
		dst.FormationPollTimeout = time.Duration(*f.FormationPollTimeoutMs) * time.Millisecond
	}
	if f.BusyProbe != nil {
		dst.BusyProbe = *f.BusyProbe
	}
	if f.BusyProbeBudgetMs != nil {
		dst.BusyProbeBudget = time.Duration(*f.BusyProbeBudgetMs) * time.Millisecond
	}
	if f.SchedulerPauseToleranceMs != nil {
		dst.SchedulerPauseTolerance = time.Duration(*f.SchedulerPauseToleranceMs) * time.Millisecond
	}
	if f.SchedulerPauseRecoveryTimeoutMs != nil {
		dst.SchedulerPauseRecoveryTimeout = time.Duration(*f.SchedulerPauseRecoveryTimeoutMs) * time.Millisecond
	}
	if f.BlackholeConnectComparativeTimeoutMs != nil {
		dst.BlackholeConnectComparativeTimeout = time.Duration(*f.BlackholeConnectComparativeTimeoutMs) * time.Millisecond
	}
	if f.HeartbeatIntervalMs != nil {
		dst.HeartbeatInterval = time.Duration(*f.HeartbeatIntervalMs) * time.Millisecond
	}

}

// maxReliabilityMs is the largest millisecond value that still fits a
// time.Duration (about 292 years).
const maxReliabilityMs = math.MaxInt64 / int64(time.Millisecond)

// validateReliabilityFile refuses a duration that is negative or too large for
// time.Duration. Past the limit the conversion wraps to a negative duration,
// and time.NewTicker panics on one. It walks the file shape by reflection, so a
// duration field added later is covered as long as its name ends in Ms.
func validateReliabilityFile(f *reliabilityFile) error {
	if f == nil {
		return nil
	}
	v := reflect.ValueOf(f).Elem()
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !strings.HasSuffix(name, "Ms") || v.Field(i).IsNil() {
			continue
		}
		ms, ok := v.Field(i).Interface().(*int64)
		if !ok {
			return fmt.Errorf("%s is not an int64 millisecond value", name)
		}
		if *ms < 0 || *ms > maxReliabilityMs {
			return fmt.Errorf("%s = %d ms is out of range, it must be between 0 and %d", name, *ms, maxReliabilityMs)
		}
	}
	return nil
}

// mergeReliabilitySettings returns a copy of cur with the fields f names
// overwritten. A field f does not name keeps its current value, including the
// fields the file shape has no entry for. It refuses an out-of-range duration
// and changes nothing in that case.
func mergeReliabilitySettings(cur *connect.ReliabilitySettings, f reliabilityFile) (*connect.ReliabilitySettings, error) {
	if err := validateReliabilityFile(&f); err != nil {
		return nil, err
	}
	merged := connect.ReliabilitySettings{}
	if cur != nil {
		merged = *cur
	}
	applyFileToSettings(&merged, &f)
	return &merged, nil
}
