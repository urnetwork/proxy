package proxy

import "sync/atomic"

// SocksStats counts events on the user-driven data path.
//
// NOTHING on that path logs. A client controls how often every one of these
// fires — it can send oversize datagrams, or aim at undialable destinations, as
// fast as its link allows — so logging them would hand it a log-amplification
// vector: one cheap packet buys a disk write and a serialized log call. At a few
// hundred thousand packets a second that is a denial of service against the
// server, driven entirely by the client, with the server paying.
//
// So these are counted instead. A counter is an atomic increment on an
// already-hot cache line; a log line is I/O. Whatever watches the process can
// sample Snapshot as often as it likes and see exactly the same information,
// without the client being able to make that observation expensive.
//
// The only thing that still logs is a panic, which is a bug in the server rather
// than something a client is entitled to cause.
type SocksStats struct {
	// CONNECT
	ConnectDialErrors atomic.Uint64

	// ASSOCIATE, client -> destination
	AssociateOversizeDatagrams  atomic.Uint64 // over MaxDatagramSize: dropped, never truncated
	AssociateMalformedDatagrams atomic.Uint64 // unparseable, or fragmented (FRAG != 0)
	AssociateForeignDatagrams   atomic.Uint64 // from a source other than the pinned client
	AssociateDialErrors         atomic.Uint64
	AssociateSendErrors         atomic.Uint64

	// ASSOCIATE, destination -> client
	AssociateOversizeReplies atomic.Uint64
	AssociateReplyErrors     atomic.Uint64

	// ASSOCIATE flow table
	AssociateFlowsOpened  atomic.Uint64
	AssociateFlowsEvicted atomic.Uint64
}

// SocksStatsSnapshot is a plain-value copy of SocksStats, for reporting.
type SocksStatsSnapshot struct {
	ConnectDialErrors uint64

	AssociateOversizeDatagrams  uint64
	AssociateMalformedDatagrams uint64
	AssociateForeignDatagrams   uint64
	AssociateDialErrors         uint64
	AssociateSendErrors         uint64

	AssociateOversizeReplies uint64
	AssociateReplyErrors     uint64

	AssociateFlowsOpened  uint64
	AssociateFlowsEvicted uint64
}

func (self *SocksStats) Snapshot() SocksStatsSnapshot {
	return SocksStatsSnapshot{
		ConnectDialErrors: self.ConnectDialErrors.Load(),

		AssociateOversizeDatagrams:  self.AssociateOversizeDatagrams.Load(),
		AssociateMalformedDatagrams: self.AssociateMalformedDatagrams.Load(),
		AssociateForeignDatagrams:   self.AssociateForeignDatagrams.Load(),
		AssociateDialErrors:         self.AssociateDialErrors.Load(),
		AssociateSendErrors:         self.AssociateSendErrors.Load(),

		AssociateOversizeReplies: self.AssociateOversizeReplies.Load(),
		AssociateReplyErrors:     self.AssociateReplyErrors.Load(),

		AssociateFlowsOpened:  self.AssociateFlowsOpened.Load(),
		AssociateFlowsEvicted: self.AssociateFlowsEvicted.Load(),
	}
}

// SocksStats returns the server's live counters. The returned pointer is stable for
// the server's lifetime; call Snapshot to read a consistent copy.
func (s *socksServer) Stats() *SocksStats {
	return &s.stats
}
