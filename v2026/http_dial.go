// Owns the detached transport dial callbacks and the connections they create
// until their request has finished. All ownership state is safe for concurrent use.
package proxy

import (
	"context"
	"net"
	"sync"
)

// Admission belongs to one already-admitted request, so graceful proxy draining
// still permits its retries. Sealing this owner prevents any late transport
// callback from entering the caller's authentication or device work.
type httpDialOwner struct {
	ctx    context.Context
	cancel context.CancelFunc

	stateLock sync.Mutex
	closed    bool
	workers   sync.WaitGroup
	connKVs   map[*httpDialConn]bool
}

// Derives cancellation from the request, which net/http deliberately detaches
// from its dial context to support transport connection reuse.
func newHttpDialOwner(ctx context.Context) *httpDialOwner {
	ctx, cancel := context.WithCancel(ctx)
	return &httpDialOwner{
		ctx:     ctx,
		cancel:  cancel,
		connKVs: map[*httpDialConn]bool{},
	}
}

// Counts a callback before entering caller code and retains successful
// connections until transport close or request teardown has closed them.
func (self *httpDialOwner) dial(dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if self.ctx.Err() != nil {
		return nil, context.Canceled
	}
	admitted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.workers.Add(1)
		return true
	}()
	if !admitted {
		return nil, context.Canceled
	}
	defer self.workers.Done()

	conn, err := dial(self.ctx)
	if conn == nil {
		return nil, err
	}
	ownedConn := &httpDialConn{Conn: conn, owner: self}
	canceled := self.ctx.Err() != nil
	retained := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if err != nil || self.closed || canceled {
			return false
		}
		self.connKVs[ownedConn] = true
		return true
	}()
	if !retained {
		// A canceled callback can return success anyway. Close before dropping
		// its worker count, without handing the connection to the transport.
		ownedConn.Close()
		if err == nil {
			err = context.Canceled
		}
		return nil, err
	}
	return ownedConn, nil
}

// Seals admission before waiting, cancels the request's dials, and closes every
// connection still owned even if net/http has not resumed after dial return.
func (self *httpDialOwner) closeAndWait(closeIdleConnections func()) {
	conns := func() []*httpDialConn {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		conns := make([]*httpDialConn, 0, len(self.connKVs))
		for conn := range self.connKVs {
			conns = append(conns, conn)
		}
		return conns
	}()
	self.cancel()
	closeIdleConnections()
	for _, conn := range conns {
		conn.Close()
	}
	self.workers.Wait()
}

// Keeps Close single-owner even when transport and request cleanup race. The
// owner retains it until the underlying Close has completed, not just started.
type httpDialConn struct {
	net.Conn
	owner     *httpDialOwner
	closeOnce sync.Once
	closeErr  error
}

// Retires transport-closed connections immediately so repeated retries cannot
// accumulate closed connections in a long-lived request.
func (self *httpDialConn) Close() error {
	self.closeOnce.Do(func() {
		self.closeErr = self.Conn.Close()
		self.owner.stateLock.Lock()
		defer self.owner.stateLock.Unlock()
		delete(self.owner.connKVs, self)
	})
	return self.closeErr
}
