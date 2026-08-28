package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// SocksRequest is the parsed SOCKS5 request passed to ConnectDialWithRequest.
type SocksRequest = *Request

// SocksProxySettings configures a SocksProxy. Take DefaultSocksProxySettings and
// adjust it; nothing is left to a zero value meaning "default".
type SocksProxySettings struct {
	// Log receives socks proxy logging. nil resolves to `connect.DefaultLogger()`.
	Log connect.Logger

	// ProxyReadTimeout bounds each read on the data path. A tunnel idle for
	// longer is torn down, and it gates SOCKS half-close. See `SocksProxySettings`.
	ProxyReadTimeout time.Duration
	// ProxyWriteTimeout bounds each write.
	ProxyWriteTimeout time.Duration
	// HandshakeTimeout bounds negotiation and request parsing.
	HandshakeTimeout time.Duration

	// AssociateIdleTimeout reclaims a UDP flow idle in both directions.
	AssociateIdleTimeout time.Duration
	// AssociateMaxFlows caps concurrent UDP flows per association. This bounds how
	// much memory one client can pin, since each flow holds a buffer and an egress
	// endpoint for its life.
	AssociateMaxFlows int
	// MaxDatagramSize is the largest UDP payload the associate relay carries.
	// Larger datagrams are dropped, never truncated.
	MaxDatagramSize int

	// StatsLogInterval is how often the data path's counters are flushed to the
	// log (only when they have changed). The data path itself never logs. Zero
	// disables the flush.
	StatsLogInterval time.Duration
}

func DefaultSocksProxySettings() *SocksProxySettings {
	return &SocksProxySettings{
		// read exceeds write deliberately: a read is an idle tunnel waiting for
		// traffic, while a write that cannot drain means the peer stopped reading
		ProxyReadTimeout:  30 * time.Second,
		ProxyWriteTimeout: 15 * time.Second,
		HandshakeTimeout:  30 * time.Second,

		AssociateIdleTimeout: 60 * time.Second,
		AssociateMaxFlows:    64,
		MaxDatagramSize:      4096,

		StatsLogInterval: DefaultStatsLogInterval,
	}
}

type SocksProxy struct {
	settings *SocksProxySettings

	// server is built ONCE, on first use, and shared across every ListenAndServe
	// (the caller runs one per address family). Building it per call would give each
	// listener its own Stats, so the counters would be split and unreachable — and
	// counters are the only observability the data path has, since it never logs.
	//
	// Building it lazily rather than in the constructor is what lets a caller adjust
	// Settings() after construction and still have it take effect. The freeze point
	// is the first build — ensureServer — not serving start.
	//
	// serverMu guards both serverOnce and server so a read-only accessor can check
	// whether the server exists without building it (building would freeze the
	// configuration mid-setup). Once built, server is never replaced.
	serverOnce sync.Once
	serverMu   sync.Mutex
	server     *socksServer

	statsLogOnce sync.Once

	ConnectDialWithRequest func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error)
	ValidUser              func(user string, password string, userAddr string) bool
}

func NewSocksProxy(settings *SocksProxySettings) *SocksProxy {
	return &SocksProxy{
		settings: settings,
	}
}

func NewSocksProxyWithDefaults() *SocksProxy {
	return NewSocksProxy(DefaultSocksProxySettings())
}

func (self *SocksProxy) Settings() *SocksProxySettings {
	return self.settings
}

func (self *SocksProxy) logger() connect.Logger {
	if self.settings.Log != nil {
		return self.settings.Log
	}
	return connect.DefaultLogger()
}

// Stats returns the socks data path's counters. Nothing on that path logs — a
// client picks the rate, so logging would let it drive unbounded server I/O — so
// these counters are how drops, dial failures and oversize datagrams are observed.
// Read-only: it does not build the server, so reading it cannot freeze the
// configuration. Zero values are returned before the server exists.
func (self *SocksProxy) Stats() SocksStatsSnapshot {
	if server := self.builtServer(); server != nil {
		return server.Stats().Snapshot()
	}
	return SocksStatsSnapshot{}
}

// Drain begins a graceful drain (PROXYDRAIN1.md §3.2): listeners close while
// in-flight connections (CONNECT relays and UDP associations) keep relaying.
// The caller waits with `WaitIdle` (or a deadline) and then cancels the serve
// ctx, which remains the hard teardown for stragglers.
func (self *SocksProxy) Drain() {
	self.ensureServer().drain.Drain()
}

// ActiveCount reports the number of in-flight connections. Read-only: it does
// not build the server, so reading it cannot freeze the configuration.
func (self *SocksProxy) ActiveCount() int {
	if server := self.builtServer(); server != nil {
		return server.drain.ActiveCount()
	}
	return 0
}

// WaitIdle blocks until a drain has begun and no connections are active, or
// ctx is done. It returns true when idle was reached.
func (self *SocksProxy) WaitIdle(ctx context.Context) bool {
	return self.ensureServer().drain.WaitIdle(ctx)
}

// builtServer returns the server if it has already been built, or nil. Read-only
// accessors use this so that reading a counter cannot freeze the configuration.
func (self *SocksProxy) builtServer() *socksServer {
	self.serverMu.Lock()
	defer self.serverMu.Unlock()
	return self.server
}

// ensureServer builds the socks5 server on first use. Settings are read here, so
// a caller may adjust Settings() any time before the first build.
func (self *SocksProxy) ensureServer() *socksServer {
	self.serverOnce.Do(func() {
		self.serverMu.Lock()
		defer self.serverMu.Unlock()
		self.server = self.newServer()
	})
	return self.server
}

// newServer builds the socks5 protocol server. The callbacks recover panics via
// connect.HandleError, matching the behavior the proxy has always had. Callback
// fields (ConnectDialWithRequest, ValidUser) are captured at build time so the
// configuration freezes atomically with the build; reading them dynamically
// inside the closures would race a concurrent assignment.
func (self *SocksProxy) newServer() *socksServer {
	server := newSocksServer(self.settings)
	server.Log = self.logger()
	dial := self.ConnectDialWithRequest
	server.Dial = func(ctx context.Context, r *Request, network string, addr string) (net.Conn, error) {
		return connect.HandleError2(func() (net.Conn, error) {
			return dial(ctx, r, network, addr)
		}, func() (net.Conn, error) {
			return nil, fmt.Errorf("Unexpected error")
		})
	}
	// nil ValidUser means no-auth allowed, preserving pre-rewrite behavior
	if validUser := self.ValidUser; validUser != nil {
		server.ValidUser = func(user string, password string, userAddr string) bool {
			return connect.HandleError1(func() bool {
				return validUser(user, password, userAddr)
			}, func() bool {
				return false
			})
		}
	}
	return server
}

func (self *SocksProxy) ListenAndServe(ctx context.Context, network string, addr string) error {
	server := self.ensureServer()

	// one flusher, however many address families are served
	self.statsLogOnce.Do(func() {
		go connect.HandleError(func() {
			logStatsPeriodically(ctx, self.logger(), "[socks]", self.settings.StatsLogInterval, self.Stats)
		})
	})

	return server.ListenAndServe(ctx, network, addr)
}
