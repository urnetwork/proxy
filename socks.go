package proxy

import (
	"context"
	// "crypto/tls"
	// "encoding/base64"
	"fmt"
	"net"
	// "net/http"
	// "net/netip"
	// "os"
	"io"
	"strings"
	// "syscall"
	"time"

	// "github.com/elazarl/goproxy"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/glog"
)


type SocksRequest = *socks5.Request


type SocksProxy struct {
	ProxyReadTimeout time.Duration
	ProxyWriteTimeout time.Duration
	ConnectDialWithRequest func(ctx context.Context, r SocksRequest, network string, addr string) (net.Conn, error)
	ValidUser func(user string, password string, userAddr string) bool
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
		socks5.WithConnectHandle(func(ctx context.Context, writer io.Writer, r SocksRequest)(error) {
			return connect.HandleError1(func()(error) {
				return self.connectHandle(ctx, writer, r)
			}, func()(error) {
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
	defer l.Close()

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
	proxyConn, err := self.ConnectDialWithRequest(ctx, r, "tcp", r.DestAddr.String())
	if err != nil {
		msg := err.Error()
		resp := statute.RepHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = statute.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = statute.RepNetworkUnreachable
		}
		socks5.SendReply(writer, resp, nil)
		return err
	}
	defer proxyConn.Close()

	if err := socks5.SendReply(writer, statute.RepSuccess, proxyConn.LocalAddr()); err != nil {
		return err
	}

	handleCtx, handleCancel := context.WithCancel(ctx)
	defer handleCancel()

	errs := make(chan error)

	go connect.HandleError(func() {
		defer handleCancel()
		_, err := copyBufferWithTimeout(proxyConn, r.Reader, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
		select {
		case <- handleCtx.Done():
		case errs <- err:
		}
	})

	go connect.HandleError(func() {
		defer handleCancel()
		_, err := copyBufferWithTimeout(writer, proxyConn, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
		select {
		case <- handleCtx.Done():
		case errs <- err:
		}
	})

	for {
		select {
		case <- handleCtx.Done():
			return nil
		case err := <- errs:
			return err
		}
	}
}


// socks.Logger
func (self *SocksProxy) Errorf(format string, args ...any) {
	glog.Errorf("[socks]"+format, args...)
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
	// names are not resolved locally
	return ctx, net.ParseIP("0.0.0.0").To4(), nil
}


