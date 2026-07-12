package proxy

import (
	"context"
	"io"
	"time"
)

// copyBufferWithTimeout copies src to dst until EOF, error, or ctx cancellation,
// applying read and write timeouts. See `relay.Copy`.
func copyBufferWithTimeout(
	ctx context.Context,
	dst io.Writer,
	src io.Reader,
	readTimeout time.Duration,
	writeTimeout time.Duration,
) (int64, error) {
	return relayCopy(ctx, dst, src, messagePoolBuffers{}, readTimeout, writeTimeout, nil)
}

// copyBufferWithTimeoutAndFlush is `copyBufferWithTimeout` with a flush after
// each write, for streaming responses.
func copyBufferWithTimeoutAndFlush(
	ctx context.Context,
	dst io.Writer,
	src io.Reader,
	readTimeout time.Duration,
	writeTimeout time.Duration,
	flush func(),
) (int64, error) {
	return relayCopy(ctx, dst, src, messagePoolBuffers{}, readTimeout, writeTimeout, flush)
}

// copyConn relays between a client conn and a proxied conn. Canceling ctx (or
// either direction ending) tears the whole relay down: both endpoints are
// deadline-poisoned and closed, so a goroutine blocked in either a read or a
// write is guaranteed to return. See `relay.Bidi`.
func copyConn(
	ctx context.Context,
	cancel context.CancelFunc,
	conn io.ReadWriter,
	proxyConn io.ReadWriter,
	readTimeout time.Duration,
	writeTimeout time.Duration,
) error {
	return copyRw(ctx, cancel, conn, conn, proxyConn, proxyConn, readTimeout, writeTimeout)
}

// copyRw relays between a client and a proxied endpoint whose read and write
// halves are separate. See `copyConn`.
//
// Half-close is NOT propagated here. HTTP request bodies are always
// self-delimiting (Content-Length or chunked), so an HTTP client never signals
// end-of-request by shutting down its write side, and treating a client's FIN as
// anything other than "this connection is over" would only delay teardown.
func copyRw(
	ctx context.Context,
	cancel context.CancelFunc,
	connReader io.Reader,
	connWriter io.Writer,
	proxyConnReader io.Reader,
	proxyConnWriter io.Writer,
	readTimeout time.Duration,
	writeTimeout time.Duration,
) error {
	return relayBidi(
		ctx,
		cancel,
		relayEndpoint{Reader: connReader, Writer: connWriter},
		relayEndpoint{Reader: proxyConnReader, Writer: proxyConnWriter},
		relayConfig{
			Buffers:      messagePoolBuffers{},
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		},
	)
}
