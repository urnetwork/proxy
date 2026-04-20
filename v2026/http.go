package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	// "errors"
	"fmt"
	// "sync"
	"bytes"

	"github.com/urnetwork/connect/v2026"
)

// a simple http/https proxy focused on proper file descriptor management

type HttpProxy struct {
	ProxyReadTimeout  time.Duration
	ProxyWriteTimeout time.Duration
	ProxyIdleTimeout  time.Duration
	// only used for http proxy
	ProxyTlsHandshakeTimeout time.Duration
	MaxHttpBodyBytes         int64
	ConnectDialWithRequest   func(r *http.Request, network string, addr string) (net.Conn, error)
	GetTlsConfigForClient    func(*tls.ClientHelloInfo) (*tls.Config, error)
}

func NewHttpProxy() *HttpProxy {
	return &HttpProxy{
		MaxHttpBodyBytes: 2 * 1024 * 1024,
	}
}

func (self *HttpProxy) ListenAndServe(ctx context.Context, network string, addr string) error {

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      self,
		ReadTimeout:  self.ProxyReadTimeout,
		WriteTimeout: self.ProxyWriteTimeout,
		IdleTimeout:  self.ProxyIdleTimeout,
	}

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

	return httpServer.Serve(l)
}

func (self *HttpProxy) ListenAndServeTls(ctx context.Context, network string, addr string) error {

	tlsConfig := &tls.Config{
		GetConfigForClient: self.GetTlsConfigForClient,
	}

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      self,
		TLSConfig:    tlsConfig,
		ReadTimeout:  self.ProxyReadTimeout,
		WriteTimeout: self.ProxyWriteTimeout,
		IdleTimeout:  self.ProxyIdleTimeout,
	}

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

	return httpServer.ServeTLS(l, "", "")
}

func (self *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	connect.HandleError(func() {
		if r.Method == http.MethodConnect {
			self.handleHttps(w, r)
		} else {
			self.handleHttp(w, r)
		}
	})
}

func (self *HttpProxy) handleHttps(w http.ResponseWriter, r *http.Request) {
	hij := w.(http.Hijacker)

	conn, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()
	go connect.HandleError(func() {
		defer conn.Close()
		select {
		case <-handleCtx.Done():
		}
	})

	// r.URL.Host contains both the host and port (if specified)
	var proxyConn net.Conn
	for {
		select {
		case <-handleCtx.Done():
			httpError(conn, http.StatusBadGateway, err)
			return
		default:
		}
		proxyConn, err = self.ConnectDialWithRequest(r, "tcp", r.URL.Host)
		if err == nil {
			break
		}
	}
	defer proxyConn.Close()

	_, err = conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		return
	}

	copyConn(handleCtx, handleCancel, conn, proxyConn, self.ProxyReadTimeout, self.ProxyWriteTimeout)
}

func (self *HttpProxy) handleHttp(w http.ResponseWriter, r *http.Request) {
	// r.Header.Del("Accept-Encoding")
	// r.Header.Del("Proxy-Connection")
	// r.Header.Del("Proxy-Authenticate")
	// r.Header.Del("Proxy-Authorization")

	b := bytes.NewBuffer(nil)
	_, err := copyBufferWithTimeout(b, io.LimitReader(r.Body, self.MaxHttpBodyBytes), nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
	r.Body.Close()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	bodyBytes := b.Bytes()

	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()

	tr := &http.Transport{
		Dial: func(network string, addr string) (net.Conn, error) {
			return connect.HandleError2(func() (net.Conn, error) {
				return self.ConnectDialWithRequest(r, network, addr)
			}, func() (net.Conn, error) {
				return nil, fmt.Errorf("Unexpected error")
			})
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   self.ProxyTlsHandshakeTimeout,
		ResponseHeaderTimeout: self.ProxyReadTimeout,
	}

	var response *http.Response
	for {
		select {
		case <-handleCtx.Done():
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		default:
		}
		r2, err := http.NewRequestWithContext(
			r.Context(),
			r.Method,
			r.URL.String(),
			bytes.NewReader(bodyBytes),
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response, err = tr.RoundTrip(r2)
		if err == nil {
			break
		}
	}
	defer response.Body.Close()

	h := w.Header()
	for k := range w.Header() {
		h.Del(k)
	}
	for k, vs := range response.Header {
		h[k] = vs
	}
	w.WriteHeader(response.StatusCode)

	if headerContains(response.Header, "connection", "upgrade") && headerContains(response.Header, "upgrade", "websocket") {
		hij := w.(http.Hijacker)

		conn, _, err := hij.Hijack()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		go connect.HandleError(func() {
			defer conn.Close()
			select {
			case <-handleCtx.Done():
			}
		})

		proxyRw := response.Body.(io.ReadWriter)

		copyConn(handleCtx, handleCancel, conn, proxyRw, self.ProxyReadTimeout, self.ProxyWriteTimeout)
	} else {
		var flush func()

		chunked := false
		if strings.HasPrefix(strings.ToLower(h.Get("content-type")), "text/event-stream") {
			chunked = true
		}
		if strings.Contains(strings.ToLower(h.Get("transfer-encoding")), "chunked") {
			chunked = true
		}
		if chunked {
			f := w.(http.Flusher)
			flush = f.Flush
		}
		_, err := copyBufferWithTimeoutAndFlush(w, response.Body, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout, flush)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		}
	}
}

func headerContains(h http.Header, name string, value string) bool {
	value = strings.ToLower(value)
	for _, v := range h.Values(name) {
		for _, s := range strings.Split(strings.ToLower(v), ",") {
			if value == s {
				return true
			}
		}
	}
	return false
}

// for a hijacked connection
func httpError(w io.Writer, statusCode int, err error) error {
	errorMessage := err.Error()
	errStr := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode,
		http.StatusText(statusCode),
		len(errorMessage),
		errorMessage,
	)
	_, writeErr := io.WriteString(w, errStr)
	return writeErr
}
