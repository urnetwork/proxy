package proxy

import (
	"context"
	"io"
	"net"
	"time"
)

// socksDeadlineReader lets the CONNECT data path read buffered handshake bytes (via
// the bufio.Reader) while still driving read deadlines on the underlying
// connection, which the relay needs to apply read timeouts and to force a
// blocked read to return on teardown.
//
// It also forwards CloseWrite so the relay can propagate a half-close to the
// client (see `socksRelayConns`); the embedded bufio.Reader would otherwise hide it.
type socksDeadlineReader struct {
	io.Reader
	conn net.Conn
}

func (self socksDeadlineReader) SetReadDeadline(t time.Time) error {
	return self.conn.SetReadDeadline(t)
}

// socksRelayConns shuttles bytes in both directions until the relay ends or ctx is
// canceled, then forces any parked direction to unwind. Cancellation closes both
// endpoints, so a goroutine blocked in either a read or a write is guaranteed to
// return and the caller's own Close defers can run. See `relay.Bidi`.
//
// Half-close IS propagated here, unlike the http proxy. SOCKS carries arbitrary
// TCP, and "send request, shut down the write side, read the response" is a
// common idiom outside HTTP; tearing the whole tunnel down on the client's FIN
// silently drops the response for those protocols.
func socksRelayConns(
	ctx context.Context,
	cancel context.CancelFunc,
	client relayEndpoint,
	target relayEndpoint,
	readTimeout time.Duration,
	writeTimeout time.Duration,
) error {
	return relayBidi(
		ctx,
		cancel,
		client,
		target,
		relayConfig{
			Buffers:      messagePoolBuffers{},
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			HalfClose:    true,
		},
	)
}
