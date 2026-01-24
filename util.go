package proxy

import (
	// "context"
	// "net"
	// "net/http"
	"io"
	"time"
	// "strings"
	"errors"
	// "fmt"
	// "sync"

	"github.com/urnetwork/connect"
)



func copyBufferWithTimeout(dst io.Writer, src io.Reader, buf []byte, readTimeout time.Duration, writeTimeout time.Duration) (written int64, err error) {
	return copyBufferWithTimeoutAndFlush(dst, src, buf, readTimeout, writeTimeout, nil)
}

// based on `io.copyBuffer` with changes:
// - default buffer 2kib
// - read and write timeouts
// - optional flush
func copyBufferWithTimeoutAndFlush(dst io.Writer, src io.Reader, buf []byte, readTimeout time.Duration, writeTimeout time.Duration, flush func()) (written int64, err error) {
	if buf == nil {
		size := 2048
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
