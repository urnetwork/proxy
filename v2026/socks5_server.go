package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/urnetwork/connect/v2026"
)

// socksDialFunc dials an egress connection for a request. network is "tcp" or "udp".
// The same callback serves CONNECT and every UDP ASSOCIATE flow, so all egress
// goes through one path (e.g. a tunnel dialer).
type socksDialFunc func(ctx context.Context, req *Request, network, addr string) (net.Conn, error)

// socksServer is a SOCKS5 server. Build it with newSocksServer.
type socksServer struct {
	settings *SocksProxySettings

	// Dial performs egress. Required.
	Dial socksDialFunc

	// ValidUser authenticates username/password. If nil, "no authentication"
	// is offered instead; if non-nil, username/password auth is required.
	ValidUser func(user, pass, userAddr string) bool

	// Log receives PANICS only. Nothing on the user-driven data path logs — a
	// client would be able to drive it at line rate. See socks5_stats.go.
	Log connect.Logger

	stats SocksStats
}

func newSocksServer(settings *SocksProxySettings) *socksServer {
	return &socksServer{settings: settings}
}

func (s *socksServer) logger() connect.Logger {
	if s.Log != nil {
		return s.Log
	}
	return connect.DefaultLogger()
}

// ListenAndServe listens on network/addr and serves connections until ctx is
// canceled or Accept fails. Each connection is served on its own goroutine with
// panic isolation; canceling ctx also tears down in-flight associations.
func (s *socksServer) ListenAndServe(ctx context.Context, network, addr string) error {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-runCtx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			// A connection that fails to serve is a normal, client-driven outcome
			// (a bad handshake, an unreachable destination, a client that hung up).
			// Logging it would let a client drive unbounded log I/O, so it is not
			// logged; ServeConn records what it needs in SocksStats.
			s.ServeConn(runCtx, conn)
		}()
	}
}

// ServeConn serves a single SOCKS5 connection to completion and closes it.
func (s *socksServer) ServeConn(ctx context.Context, conn net.Conn) (err error) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			s.logger().Errorf("[socks]panic serving %v: %v", conn.RemoteAddr(), r)
			err = fmt.Errorf("socks5: panic: %v", r)
		}
	}()

	if hs := s.settings.HandshakeTimeout; 0 < hs {
		conn.SetDeadline(time.Now().Add(hs))
	}

	br := bufio.NewReader(conn)

	authCtx, err := s.negotiate(conn, br)
	if err != nil {
		return err
	}

	req, err := readRequest(br)
	if err != nil {
		if errors.Is(err, errUnrecognizedAddrType) {
			writeReply(conn, repAddrTypeNotSupported, nil)
		}
		return err
	}
	req.AuthContext = authCtx
	req.LocalAddr = conn.LocalAddr()
	req.RemoteAddr = conn.RemoteAddr()

	switch req.Command {
	case cmdConnect:
		return s.handleConnect(ctx, conn, br, req)
	case cmdAssociate:
		return s.handleAssociate(ctx, conn, req)
	default:
		writeReply(conn, repCommandNotSupported, nil)
		return fmt.Errorf("socks5: unsupported command %#x", req.Command)
	}
}

// negotiate performs method selection and authentication.
func (s *socksServer) negotiate(conn net.Conn, br *bufio.Reader) (*AuthContext, error) {
	methods, err := readMethods(br)
	if err != nil {
		return nil, err
	}

	userAddr := ""
	if conn.RemoteAddr() != nil {
		userAddr = conn.RemoteAddr().String()
	}

	if s.ValidUser != nil {
		if !containsByte(methods, methodUserPass) {
			conn.Write([]byte{socksVersion, methodNoAcceptable})
			return nil, errNoAcceptableAuth
		}
		if _, err := conn.Write([]byte{socksVersion, methodUserPass}); err != nil {
			return nil, err
		}
		user, pass, err := readUserPass(br)
		if err != nil {
			return nil, err
		}
		if !s.ValidUser(user, pass, userAddr) {
			conn.Write([]byte{userPassVersion, authFailure})
			return nil, errAuthFailed
		}
		if _, err := conn.Write([]byte{userPassVersion, authSuccess}); err != nil {
			return nil, err
		}
		return &AuthContext{
			Method:  methodUserPass,
			Payload: map[string]string{"username": user, "password": pass},
		}, nil
	}

	if !containsByte(methods, methodNoAuth) {
		conn.Write([]byte{socksVersion, methodNoAcceptable})
		return nil, errNoAcceptableAuth
	}
	if _, err := conn.Write([]byte{socksVersion, methodNoAuth}); err != nil {
		return nil, err
	}
	return &AuthContext{Method: methodNoAuth, Payload: map[string]string{}}, nil
}

// handleConnect handles a CONNECT request: dial the target, reply, then relay.
func (s *socksServer) handleConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, req *Request) error {
	target, err := s.Dial(ctx, req, "tcp", req.DestAddr.String())
	if err != nil {
		s.stats.ConnectDialErrors.Add(1)
		writeReply(conn, socksReplyCodeForDialError(err), nil)
		return fmt.Errorf("socks5: connect %s: %w", req.DestAddr, err)
	}
	defer target.Close()

	// The data phase manages its own deadlines.
	conn.SetDeadline(time.Time{})

	if err := writeReply(conn, repSuccess, target.LocalAddr()); err != nil {
		return err
	}

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	return socksRelayConns(
		relayCtx,
		cancel,
		relayEndpoint{Reader: socksDeadlineReader{Reader: br, conn: conn}, Writer: conn},
		relayEndpoint{Reader: target, Writer: target},
		s.settings.ProxyReadTimeout,
		s.settings.ProxyWriteTimeout,
	)
}

// socksReplyCodeForDialError maps a dial error to a SOCKS5 reply code, handling both
// syscall errno wrapping and the string forms surfaced by gVisor/gonet.
func socksReplyCodeForDialError(err error) uint8 {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return repHostUnreachable
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused"):
		return repConnectionRefused
	case strings.Contains(msg, "network is unreachable"):
		return repNetworkUnreachable
	default:
		return repHostUnreachable
	}
}
