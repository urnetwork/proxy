package proxy

import (
	"context"
	"net"
	"net/http"
	"io"
	"time"
	"strings"
	"errors"
	"fmt"
	// "sync"

	"github.com/urnetwork/connect"
)


// a simple http/https proxy focused on proper file descriptor management


type HttpProxy struct {
	ProxyReadTimeout time.Duration
	ProxyWriteTimeout time.Duration
	// only used for http proxy
	ProxyTlsHandshakeTimeout time.Duration
	ConnectDialWithRequest func(r *http.Request, network string, addr string) (net.Conn, error)
}

func NewHttpProxy() *HttpProxy {
	return &HttpProxy{}
}

func (self *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		self.handleHttps(w, r)
	} else {
		self.handleHttp(w, r)
	}
}


func (self *HttpProxy) handleHttps(w http.ResponseWriter, r *http.Request) {
	hij := w.(http.Hijacker)

	conn, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// r.URL.Host contains both the host and port (if specified)
	proxyConn, err := self.ConnectDialWithRequest(r, "tcp", r.URL.Host)
	if err != nil {
		httpError(conn, http.StatusBadGateway, err)
		return
	}
	defer proxyConn.Close()

	conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	handleCtx, handleCancel := context.WithCancel(r.Context())
	defer handleCancel()

	go connect.HandleError(func() {
		defer handleCancel()
		copyBufferWithTimeout(proxyConn, conn, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
	})

	go connect.HandleError(func() {
		defer handleCancel()
		copyBufferWithTimeout(conn, proxyConn, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
	})

	select {
	case <- handleCtx.Done():
	}

	return
}

func (self *HttpProxy) handleHttp(w http.ResponseWriter, r *http.Request) {
	// r.Header.Del("Accept-Encoding")
	// r.Header.Del("Proxy-Connection")
	// r.Header.Del("Proxy-Authenticate")
	// r.Header.Del("Proxy-Authorization")
	

	r2, err := http.NewRequestWithContext(
		r.Context(),
		r.Method,
		r.URL.String(),
		r.Body,
	)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tr := &http.Transport{
		Dial: func(network string, addr string) (net.Conn, error) {
			return self.ConnectDialWithRequest(r, network, addr)
		},
		DisableKeepAlives: true,
		TLSHandshakeTimeout: self.ProxyTlsHandshakeTimeout,
		ResponseHeaderTimeout: self.ProxyReadTimeout,
	}


	response, err := tr.RoundTrip(r2)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

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
		defer conn.Close()

		proxyRw := response.Body.(io.ReadWriter)
		defer response.Body.Close()

		handleCtx, handleCancel := context.WithCancel(r.Context())

		go connect.HandleError(func() {
			defer handleCancel()
			copyBufferWithTimeout(conn, proxyRw, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
		})

		go connect.HandleError(func() {
			defer handleCancel()
			copyBufferWithTimeout(proxyRw, conn, nil, self.ProxyReadTimeout, self.ProxyWriteTimeout)
		})

		select {
		case <- handleCtx.Done():
		}
	} else {
		defer response.Body.Close()

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


func copyBufferWithTimeout(dst io.Writer, src io.Reader, buf []byte, readTimeout time.Duration, writeTimeout time.Duration) (written int64, err error) {
	return copyBufferWithTimeoutAndFlush(dst, src, buf, readTimeout, writeTimeout, nil)
}

// based on `io.copyBuffer` with read and write timeouts
func copyBufferWithTimeoutAndFlush(dst io.Writer, src io.Reader, buf []byte, readTimeout time.Duration, writeTimeout time.Duration, flush func()) (written int64, err error) {
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = connect.MessagePoolGet(size)
		defer connect.MessagePoolReturn(buf)
	}
	for {
		if 0 < readTimeout {
			if c, ok := src.(interface{SetReadDeadline(time.Time)(error)}); ok {
				c.SetReadDeadline(time.Now().Add(readTimeout))
			}
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if 0 < writeTimeout {
				if c, ok := dst.(interface{SetWriteDeadline(time.Time)(error)}); ok {
					c.SetWriteDeadline(time.Now().Add(writeTimeout))
				}
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			if flush != nil {
				flush()
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
