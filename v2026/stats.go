package proxy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// The proxies never log on the user-driven data path. A client picks the rate at
// which connections fail, datagrams are malformed, and destinations are
// unreachable, so logging those events would let it turn one cheap packet into a
// disk write — an amplification the server pays for and the client does not.
//
// So the data path counts instead of logging, and the counters are flushed to the
// log on a fixed interval. That is safe where per-event logging is not: the rate
// is set by the SERVER, not by any client. Only a CHANGED snapshot is emitted, so
// an idle proxy stays silent.

// DefaultStatsLogInterval is how often the data path's counters are flushed.
const DefaultStatsLogInterval = 60 * time.Second

// HttpStats counts events on the http proxy's data path.
type HttpStats struct {
	// CONNECT
	ConnectDialErrors   atomic.Uint64 // an upstream dial attempt failed
	ConnectClientsGone  atomic.Uint64 // the client dropped while we were still dialing
	ConnectHijackErrors atomic.Uint64
	ConnectTimeouts     atomic.Uint64 // the dial budget ran out: answered 504

	// plain http
	RequestDialErrors   atomic.Uint64
	RequestsNotReplayed atomic.Uint64 // failed after being sent, and not idempotent: not retried
	ResponsesAborted    atomic.Uint64 // upstream died mid-body, after the head was on the wire
	BodiesTooLarge      atomic.Uint64
	UpgradeErrors       atomic.Uint64

	// definitive dial refusals, CONNECT and plain http, answered at once by
	// ConnectRefusalClass
	DialRefusedUnauthenticated atomic.Uint64 // 407
	DialRefusedForbidden       atomic.Uint64 // 403
	DialRefusedUnknownProxy    atomic.Uint64 // 502
	DialRefusedReset           atomic.Uint64 // 502
	DialRefusedNoSuchHost      atomic.Uint64 // 502
}

// HttpStatsSnapshot is a plain-value copy of HttpStats, for reporting.
type HttpStatsSnapshot struct {
	ConnectDialErrors   uint64
	ConnectClientsGone  uint64
	ConnectHijackErrors uint64
	ConnectTimeouts     uint64

	RequestDialErrors   uint64
	RequestsNotReplayed uint64
	ResponsesAborted    uint64
	BodiesTooLarge      uint64
	UpgradeErrors       uint64

	DialRefusedUnauthenticated uint64
	DialRefusedForbidden       uint64
	DialRefusedUnknownProxy    uint64
	DialRefusedReset           uint64
	DialRefusedNoSuchHost      uint64
}

func (self *HttpStats) Snapshot() HttpStatsSnapshot {
	return HttpStatsSnapshot{
		ConnectDialErrors:   self.ConnectDialErrors.Load(),
		ConnectClientsGone:  self.ConnectClientsGone.Load(),
		ConnectHijackErrors: self.ConnectHijackErrors.Load(),
		ConnectTimeouts:     self.ConnectTimeouts.Load(),

		RequestDialErrors:   self.RequestDialErrors.Load(),
		RequestsNotReplayed: self.RequestsNotReplayed.Load(),
		ResponsesAborted:    self.ResponsesAborted.Load(),
		BodiesTooLarge:      self.BodiesTooLarge.Load(),
		UpgradeErrors:       self.UpgradeErrors.Load(),

		DialRefusedUnauthenticated: self.DialRefusedUnauthenticated.Load(),
		DialRefusedForbidden:       self.DialRefusedForbidden.Load(),
		DialRefusedUnknownProxy:    self.DialRefusedUnknownProxy.Load(),
		DialRefusedReset:           self.DialRefusedReset.Load(),
		DialRefusedNoSuchHost:      self.DialRefusedNoSuchHost.Load(),
	}
}

// countRefusal counts one definitive refusal under its class.
func (self *HttpStats) countRefusal(class ConnectRefusalClass) {
	switch class {
	case ConnectRefusalUnauthenticated:
		self.DialRefusedUnauthenticated.Add(1)
	case ConnectRefusalForbidden:
		self.DialRefusedForbidden.Add(1)
	case ConnectRefusalUnknownProxy:
		self.DialRefusedUnknownProxy.Add(1)
	case ConnectRefusalReset:
		self.DialRefusedReset.Add(1)
	case ConnectRefusalNoSuchHost:
		self.DialRefusedNoSuchHost.Add(1)
	}
}

// logStatsPeriodically flushes snapshot() to the log every interval, but only when
// it has changed. Both proxies use it. See the note at the top of this file for
// why this is the only place the data path is allowed to reach a log.
func logStatsPeriodically[T comparable](
	ctx context.Context,
	log connect.Logger,
	tag string,
	interval time.Duration,
	snapshot func() T,
) {
	if interval <= 0 {
		return
	}
	var last T
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		stats := snapshot()
		if stats != last {
			log.Infof("%sstats %+v\n", tag, stats)
			last = stats
		}
	}
}
