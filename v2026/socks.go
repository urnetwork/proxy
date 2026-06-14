package proxy

import (
	"context"
	// "crypto/tls"
	// "encoding/base64"
	"errors"
	"fmt"
	"net"
	// "net/http"
	// "net/netip"
	// "os"
	"io"
	"strings"
	"syscall"
	"time"
	// "sync"

	// "github.com/elazarl/goproxy"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/urnetwork/connect/v2026"
)

type SocksRequest = *socks5.Request

type SocksProxy struct {
	// Log, when set, receives socks proxy logging. nil resolves to
	// `connect.DefaultLogger()`.
	Log connect.Logger

	ProxyReadTimeout       time.Duration
	ProxyWriteTimeout      time.Duration
	ConnectDialWithRequest func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error)
	ValidUser              func(user string, password string, userAddr string) bool
}

func NewSocksProxy() *SocksProxy {
	return &SocksProxy{}
}

func (self *SocksProxy) ListenAndServe(ctx context.Context, network string, addr string) error {

	socksServer := socks5.NewServer(
		socks5.WithLogger(self),
		socks5.WithCredential(self),
		socks5.WithResolver(self),
		socks5.WithRule(socks5.NewPermitConnAndAss()),
		socks5.WithDialAndRequest(func(ctx context.Context, network string, addr string, r *socks5.Request) (net.Conn, error) {
			return connect.HandleError2(func() (net.Conn, error) {
				return self.ConnectDialWithRequest(ctx, r, network, addr)
			}, func() (net.Conn, error) {
				return nil, fmt.Errorf("Unexpected error")
			})
		}),
		socks5.WithConnectHandle(func(ctx context.Context, writer io.Writer, r SocksRequest) error {
			return connect.HandleError1(func() error {
				return self.connectHandle(ctx, writer, r)
			}, func() error {
				return fmt.Errorf("Unexpected error")
			})
		}),
	)

	listenConfig := net.ListenConfig{}

	l, err := listenConfig.Listen(
		ctx,
		network,
		addr,
	)
	if err != nil {
		return err
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	go connect.HandleError(func() {
		defer l.Close()
		select {
		case <-runCtx.Done():
		}
	})

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go connect.HandleError(func() {
			socksServer.ServeConn(conn)
		})
	}
}

func (self *SocksProxy) connectHandle(ctx context.Context, writer io.Writer, r SocksRequest) error {
	clientConn, _ := writer.(net.Conn)
	proxyConn, err := self.ConnectDialWithRequest(ctx, r, "tcp", r.DestAddr.String())
	if err != nil {
		resp := mapDialErrorToSocksReply(err)
		socks5.SendReply(writer, resp, nil)
		return err
	}
	handleCtx, handleCancel := context.WithCancel(ctx)
	defer handleCancel()
	go connect.HandleError(func() {
		defer proxyConn.Close()
		if clientConn != nil {
			defer clientConn.Close()
		}
		select {
		case <-handleCtx.Done():
		}
	})

	if err := socks5.SendReply(writer, statute.RepSuccess, proxyConn.LocalAddr()); err != nil {
		return err
	}

	return copyRw(handleCtx, handleCancel, r.Reader, writer, proxyConn, proxyConn, self.ProxyReadTimeout, self.ProxyWriteTimeout)
}

// socks.Logger
func (self *SocksProxy) Errorf(format string, args ...any) {
	log := self.Log
	if log == nil {
		log = connect.DefaultLogger()
	}
	log.Errorf("[socks]"+format, args...)
}

// socks.CredentialStore
func (self *SocksProxy) Valid(username string, password string, userAddr string) bool {
	return connect.HandleError1(func() bool {
		return self.ValidUser(username, password, userAddr)
	}, func() bool {
		return false
	})
}

// socks.NameResolver
func (self *SocksProxy) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Names are resolved by the proxied dialer. Returning nil preserves the FQDN
	// in the request address instead of replacing it with a local resolver result.
	return ctx, nil, nil
}

func mapDialErrorToSocksReply(err error) uint8 {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return statute.RepConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return statute.RepNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return statute.RepHostUnreachable
	}
	// Fallback to substring matching for errors not wrapped as syscall codes
	// (e.g. gVisor tcpip errors surfaced through gonet).
	msg := err.Error()
	if strings.Contains(msg, "refused") {
		return statute.RepConnectionRefused
	}
	if strings.Contains(msg, "network is unreachable") {
		return statute.RepNetworkUnreachable
	}
	return statute.RepHostUnreachable
}
