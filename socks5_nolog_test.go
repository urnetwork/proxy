package proxy

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// countingLogger records everything written to it. Anything a client can drive at
// line rate must never reach one of these.
type countingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (self *countingLogger) record(format string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.lines = append(self.lines, format)
}

func (self *countingLogger) Info(args ...any)                    {}
func (self *countingLogger) Infof(format string, args ...any)    { self.record(format) }
func (self *countingLogger) Warningf(format string, args ...any) { self.record(format) }
func (self *countingLogger) Errorf(format string, args ...any)   { self.record(format) }
func (self *countingLogger) V(level int32) connect.Verbose       { return nopVerbose{} }

func (self *countingLogger) count() int {
	self.mu.Lock()
	defer self.mu.Unlock()
	return len(self.lines)
}

func (self *countingLogger) all() []string {
	self.mu.Lock()
	defer self.mu.Unlock()
	return append([]string(nil), self.lines...)
}

// TestClientDrivenTrafficNeverLogs is the regression test for log amplification.
//
// Every branch exercised here is one a client picks and can repeat as fast as its
// link allows: oversize datagrams, malformed datagrams, fragmented datagrams,
// datagrams to undialable destinations, connects to unreachable hosts. If any of
// them writes a log line, a client can convert one cheap packet into a disk write
// on the server — a denial of service the server pays for and the client does not.
//
// They must be COUNTED, not logged.
func TestClientDrivenTrafficNeverLogs(t *testing.T) {
	logger := &countingLogger{}

	settings := testSettings()
	settings.AssociateIdleTimeout = 30 * time.Second
	settings.MaxDatagramSize = 2048

	var dials atomic.Int64
	server := &socksServer{
		settings:  settings,
		Log:       logger,
		ValidUser: allowAll,
		Dial: func(ctx context.Context, req *Request, network, addr string) (net.Conn, error) {
			dials.Add(1)
			// every dial fails: the client chose an unreachable destination
			return nil, &net.OpError{Op: "dial", Err: errUnreachable{}}
		},
	}
	addr, stop := startServer(t, server)
	defer stop()

	// 1. a CONNECT to an unreachable host
	tc := dialClient(t, addr)
	tc.negotiateUserPass("u", "p")
	if rep, _ := tc.request(cmdConnect, &AddrSpec{FQDN: "unreachable.test", Port: 80}); rep == repSuccess {
		t.Fatal("expected the connect to fail")
	}
	tc.close()

	// 2. ASSOCIATE, then every kind of client-driven drop, repeatedly
	tc = dialClient(t, addr)
	defer tc.close()
	tc.negotiateUserPass("u", "p")
	bnd := tc.associate()
	uc := udpClient(t)

	dst := &AddrSpec{IP: net.IPv4(203, 0, 113, 9).To4(), Port: 9}
	for i := 0; i < 50; i += 1 {
		// oversize payload
		sendDatagram(t, uc, bnd, dst, bytes.Repeat([]byte("A"), 4096))
		// undialable destination
		sendDatagram(t, uc, bnd, dst, []byte("x"))
		// malformed: too short to be a datagram at all
		uc.WriteToUDP([]byte{0, 0}, bnd)
		// fragmented (FRAG != 0), which we do not reassemble
		frag := appendDatagramHeader(nil, dst)
		frag[2] = 1
		frag = append(frag, []byte("y")...)
		uc.WriteToUDP(frag, bnd)
	}
	time.Sleep(500 * time.Millisecond)

	if n := logger.count(); n != 0 {
		t.Fatalf("client-driven traffic produced %d log line(s): a client can drive these at line rate, "+
			"so each one is a log-amplification vector. They must be counted, not logged.\nlines: %v",
			n, logger.all())
	}

	// ...and the same events must be OBSERVABLE, or we have merely gone blind
	stats := server.Stats().Snapshot()
	if stats.ConnectDialErrors == 0 {
		t.Error("ConnectDialErrors was not counted")
	}
	if stats.AssociateOversizeDatagrams == 0 {
		t.Error("AssociateOversizeDatagrams was not counted")
	}
	if stats.AssociateMalformedDatagrams == 0 {
		t.Error("AssociateMalformedDatagrams was not counted")
	}
	if stats.AssociateDialErrors == 0 {
		t.Error("AssociateDialErrors was not counted")
	}
	t.Logf("counted instead of logged: %+v", stats)
}

type errUnreachable struct{}

func (errUnreachable) Error() string   { return "no route to host" }
func (errUnreachable) Timeout() bool   { return false }
func (errUnreachable) Temporary() bool { return false }

// TestDefaultAssociateMaxFlows pins the flow cap. It bounds how much memory one
// client can pin: each flow holds a datagram buffer, an egress endpoint and a
// goroutine for its lifetime.
func TestDefaultAssociateMaxFlows(t *testing.T) {
	if got := DefaultSocksProxySettings().AssociateMaxFlows; got != 64 {
		t.Fatalf("default AssociateMaxFlows = %d, want 64", got)
	}
}
