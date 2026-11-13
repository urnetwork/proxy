// Forces an abnormal connect dial exit while its client-close reader is still owned.
package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"testing/synctest"
)

// Retains the read's wrapper tail after the pipe operation itself has returned.
type ownershipReadTailConn struct {
	net.Conn
	readEntered chan struct{}
	tailEntered chan struct{}
	tailRelease chan struct{}
	tailDone    chan struct{}
}

// Makes an in-flight provider Read observable before and after cancellation unblocks it.
func (self *ownershipReadTailConn) Read(b []byte) (int, error) {
	close(self.readEntered)
	n, err := self.Conn.Read(b)
	close(self.tailEntered)
	<-self.tailRelease
	close(self.tailDone)
	return n, err
}

// A callback panic must still join the read worker that began before the dial.
func TestServeOwnershipConnectPanicJoinsClientWatch(t *testing.T) {
	ownershipConnectAbnormalWatch(t, false)
}

// Goexit runs scope defers even though no recovery handler can intercept it.
func TestServeOwnershipConnectGoexitJoinsClientWatch(t *testing.T) {
	ownershipConnectAbnormalWatch(t, true)
}

// Both abnormal exits must retain the client reader through its provider tail.
func ownershipConnectAbnormalWatch(t *testing.T, goexit bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		proxy := NewHttpProxy(ownershipHttpSettings())
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		conn := &ownershipReadTailConn{Conn: serverConn, readEntered: make(chan struct{}), tailEntered: make(chan struct{}), tailRelease: make(chan struct{}), tailDone: make(chan struct{})}
		proxy.ConnectDialContextWithRequest = func(context.Context, *http.Request, string, string) (net.Conn, error) {
			<-conn.readEntered
			if goexit {
				runtime.Goexit()
			}
			panic("synthetic dial panic")
		}
		request := httptest.NewRequest(http.MethodConnect, "http://panic-owner.example:443", nil)
		writer := &ownershipHijackWriter{ResponseRecorder: httptest.NewRecorder(), conn: conn}
		done := make(chan error, 1)
		go func() {
			defer func() {
				if value := recover(); !goexit && value != "synthetic dial panic" {
					t.Errorf("unexpected panic value: %v", value)
				}
				done <- nil
			}()
			proxy.handleHttps(writer, request)
		}()
		<-conn.tailEntered
		waiting := ownershipMustStillRun(t, done, "connect panic client-close watch")
		close(conn.tailRelease)
		if waiting {
			<-done
		}
		<-conn.tailDone
		conn.Close()
	})
}
