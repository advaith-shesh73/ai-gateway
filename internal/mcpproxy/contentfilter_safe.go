// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"fmt"
	"runtime/debug"
	"sync/atomic"
)

// panicRecorder is an optional callback invoked by safeGo whenever it
// recovers a panic. The callback receives the worker name. It MUST be
// cheap and non-blocking; typical implementations are a single
// Prometheus counter increment.
//
// The callback is stored atomically so it can be installed by metrics
// wiring without a startup ordering constraint, and so tests can swap
// it per-test without a data race.
var panicRecorder atomic.Pointer[func(worker string)]

// SetPanicRecorder installs a process-wide callback that [safeGo]
// invokes once per recovered panic. Pass nil to clear. Safe to call
// from any goroutine at any time. Intended wiring from the gateway
// bootstrap is:
//
//	m := NewPrometheusMetrics(registry)
//	SetPanicRecorder(m.RecordPanic)
//
// Using a global hook (rather than plumbing the metrics pointer
// through every goroutine spawn) keeps safeGo callsites short and
// noise-free — the package already has exactly one canonical metrics
// instance per process.
func SetPanicRecorder(fn func(worker string)) {
	if fn == nil {
		panicRecorder.Store(nil)
		return
	}
	panicRecorder.Store(&fn)
}

// safeGo wraps a worker function so a panic inside it becomes a returned
// error instead of crashing the whole gateway process. Use this as the
// unit of work in every `errgroup.Group.Go` call on the content-filter
// hot path.
//
// Why this exists
// ---------------
// The content-filter pipeline fans out across many goroutines — one per
// text chunk, one per content part, one per background hedge — and a
// single panic in any of them would otherwise take down the gateway
// process and, with it, every unrelated request riding the same binary.
// That is a DoS vector in all but name; the fix is to translate panics
// into structured errors at the goroutine boundary the same way a
// handler would translate a bad input.
//
// The returned error carries the goroutine's stack trace so the
// dispatcher's log line is actionable: operators can grep for
// `pii worker panic` and jump straight to the offending file:line.
// logsafe does not touch this error — it is a programmer bug, not PII.
//
// If [SetPanicRecorder] has been called, the installed callback is
// invoked with the worker name before safeGo returns, so panic counts
// are visible in mcp_filter_worker_panics_total.
func safeGo(name string, fn func() error) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("%s panic: %v\n%s", name, r, debug.Stack())
			if pr := panicRecorder.Load(); pr != nil && *pr != nil {
				(*pr)(name)
			}
		}
	}()
	return fn()
}
