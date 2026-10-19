//go:build race

package proxy

// Under the race detector the data-race scan dominates runtime, so scale the
// default client count down to keep the perf test bounded while still exercising
// the concurrent add/route paths. Override with WG_PERF_CLIENTS.
const wgPerfDefaultClients = 4 * 1024
