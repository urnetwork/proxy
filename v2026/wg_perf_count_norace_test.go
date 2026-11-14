//go:build !race

package proxy

// wgPerfDefaultClients is the default client count for the wg trickle perf test.
const wgPerfDefaultClients = 32 * 1024
