//go:build !dev

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// A release build has no control server, no panel and no --control flag. A dev
// build (go build -tags dev) adds them.

// controlUsage is empty, so --control is not in a release build's usage text.
const controlUsage = ""

// controlFlag ignores CONTROL in a release build and says so.
func controlFlag(pick func(optName string, envName string, def string) string) string {
	if os.Getenv("CONTROL") != "" {
		fmt.Fprintln(os.Stderr, "CONTROL is set, but this build has no control server (build with -tags dev)")
	}
	return ""
}

func startControl(ctx context.Context, stop context.CancelFunc, addr string, mc mcControl) error {
	return errors.New("this build has no control server (build with -tags dev)")
}
