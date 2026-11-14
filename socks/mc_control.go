package main

import "github.com/urnetwork/connect"

// mcControl is the slice of the multi client the control plane uses. The real
// *connect.RemoteUserNatMultiClient satisfies it; tests substitute a fake.
type mcControl interface {
	ReliabilitySettings() *connect.ReliabilitySettings
	SetReliabilitySettings(settings *connect.ReliabilitySettings)
	ReliabilityMetrics() *connect.ReliabilityMetricsSnapshot
	ResetReliabilityMetrics()
	Shuffle()
	ProbeAllExits() int
	Exits() []*connect.ExitInfo
	DropExit(clientId connect.Id) bool
	StallExit(clientId connect.Id, stalled bool) bool
	MigrateExit(clientId connect.Id) int
	PacketStats() *connect.PacketStats
}
