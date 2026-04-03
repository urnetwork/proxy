package proxy

import (
	"context"
	// "net"
	// "net/http"
	"io"
	// "os"
	"time"
	// "strings"
	"errors"
	// "fmt"
	// "sync"

	"github.com/urnetwork/connect/v2026"
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
		buf = connect.MessagePoolGet(2048)
		defer connect.MessagePoolReturn(buf)
	}
	for {
		if 0 < readTimeout {
			if c, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				c.SetReadDeadline(time.Now().Add(readTimeout))
			}
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if 0 < writeTimeout {
				if c, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
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

func copyConn(ctx context.Context, cancel context.CancelFunc, conn io.ReadWriter, proxyConn io.ReadWriter, readTimeout time.Duration, writeTimeout time.Duration) error {
	return copyRw(
		ctx,
		cancel,
		conn,
		conn,
		proxyConn,
		proxyConn,
		readTimeout,
		writeTimeout,
	)
}

func copyRw(ctx context.Context, cancel context.CancelFunc, connReader io.Reader, connWriter io.Writer, proxyConnReader io.Reader, proxyConnWriter io.Writer, readTimeout time.Duration, writeTimeout time.Duration) error {
	// errs := make(chan error)

	// var wg sync.WaitGroup

	// wg.Add(1)
	// go connect.HandleError(func() {
	// 	defer wg.Done()
	// 	defer cancel()
	// 	_, err := copyBufferWithTimeout(proxyConnWriter, connReader, nil, readTimeout, writeTimeout)
	// 	select {
	// 	case <- ctx.Done():
	// 	case errs <- err:
	// 	}
	// })

	// wg.Add(1)
	// go connect.HandleError(func() {
	// 	defer wg.Done()
	// 	defer cancel()

	// 	buf := connect.MessagePoolGet(2048)
	// 	defer connect.MessagePoolReturn(buf)

	// 	n := int((readTimeout + flushTimeout - 1) / flushTimeout)
	// 	for c := 0; c < n; {
	// 		n, err := copyBufferWithTimeout(connWriter, proxyConnReader, buf, flushTimeout, writeTimeout)
	// 		if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
	// 			select {
	// 			case <- ctx.Done():
	// 			case errs <- err:
	// 			}
	// 		}
	// 		if 0 < n {
	// 			c = 0
	// 		} else {
	// 			select {
	// 			case <- ctx.Done():
	// 				return
	// 			default:
	// 				c += 1
	// 			}
	// 		}
	// 	}
	// })

	// select {
	// case <- ctx.Done():
	// 	return nil
	// case err := <- errs:
	// 	wg.Wait()
	// 	return err
	// }

	errs := make(chan error)

	go connect.HandleError(func() {
		defer cancel()
		_, err := copyBufferWithTimeout(proxyConnWriter, connReader, nil, readTimeout, writeTimeout)
		select {
		case <-ctx.Done():
		case errs <- err:
		}
	})

	go connect.HandleError(func() {
		defer cancel()
		_, err := copyBufferWithTimeout(connWriter, proxyConnReader, nil, readTimeout, writeTimeout)
		select {
		case <-ctx.Done():
		case errs <- err:
		}
	})

	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}
