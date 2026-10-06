// Joins cancellation callbacks before their owners release sockets or providers.
package proxy

import (
	"context"
	"sync"
)

// Stops a callback that has not begun, or waits for the running callback to finish.
// The callback must not invoke the returned join function or re-enter owner teardown.
func afterFuncAndJoin(ctx context.Context, callback func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		callback()
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}
