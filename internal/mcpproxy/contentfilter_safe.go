// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"fmt"
	"log/slog"
	"runtime/debug"
)

// safeGo runs fn and converts any panic into a non-nil error. Intended
// to wrap goroutine bodies on gateway hot paths so that a bug in a
// downstream handler cannot crash the whole proxy process. name is a
// short, low-cardinality label used in the recovered error so
// operators can grep the log for which goroutine died.
//
// Returns fn()'s error verbatim on the happy path, or a wrapped error
// describing the panic (with stack trace attached via slog) on the
// recovery path. Callers typically log the returned error and treat
// the call as failed.
func safeGo(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			slog.Error("mcpproxy: recovered panic in safeGo",
				slog.String("worker", name),
				slog.Any("panic", r),
				slog.String("stack", string(stack)),
			)
			err = fmt.Errorf("mcpproxy: panic in %q: %v", name, r)
		}
	}()
	return fn()
}
