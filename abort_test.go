package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// A mid-body upstream failure must abort the response, not append "Bad Gateway"
// into the body the client is already reading. Exercises the ErrAbortHandler
// re-raise through connect.HandleError (which recovers every panic).
func TestMidBodyUpstreamFailureAbortsResponse(t *testing.T) {
	backend := listenTCP(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		if _, err := http.ReadRequest(reader); err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
		io.WriteString(conn, "5\r\nHELLO\r\n")
		time.Sleep(100 * time.Millisecond)
		conn.Close() // die mid-body, before the terminating chunk
	})

	proxy := NewHttpProxy(testHttpSettings())
	proxy.ConnectDialWithRequest = func(r *http.Request, network string, addr string) (net.Conn, error) {
		return (&net.Dialer{}).Dial("tcp", backend)
	}
	proxyAddr, stop := startHttpProxy(t, proxy)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	t.Logf("body=%q readErr=%v", body, err)

	if string(body) != "HELLO" {
		t.Fatalf("body = %q, want exactly the bytes the origin sent", body)
	}
	// the body must NOT be framed as complete: a truncated chunked stream must
	// surface as a read error, not a clean EOF with error text appended
	if err == nil {
		t.Fatal("truncated response was framed as complete: the client cannot tell it was cut off")
	}
}
