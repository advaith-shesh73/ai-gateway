// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import "sync/atomic"

// AtomicDispatcher is a thread-safe holder of a [*Dispatcher]. It
// exists so operators can hot-reload the content-filter policy
// (swap the backing Dispatcher) without quiescing in-flight requests.
//
// Semantics:
//   - Callers load the current dispatcher via [Get] once per request
//     and use that snapshot for the whole lifecycle of the request.
//   - A swap via [Store] is atomic; in-flight requests already holding
//     a prior snapshot continue to use the old policy until they
//     complete. This is the "old-before-new" invariant documented in
//     the Dispatcher godoc.
//   - The old [*Dispatcher] is NOT explicitly shut down. Because the
//     Dispatcher holds references to the PII / Jira clients and their
//     circuit breakers, dropping the reference after all in-flight
//     requests complete is enough — garbage collection reclaims the
//     rest. Callers who want deterministic shutdown should drain the
//     HTTP listener before calling Store(nil).
//
// A nil initial value is legal; [Get] returns nil until the first
// [Store] call installs a dispatcher. Downstream handlers MUST handle
// Get() == nil as a 503 ("filter not ready") so a racing health probe
// that arrives before the first config load doesn't panic.
type AtomicDispatcher struct {
	p atomic.Pointer[Dispatcher]
}

// NewAtomicDispatcher returns a holder primed with d (which may be
// nil). Safe to call at any time from any goroutine.
func NewAtomicDispatcher(d *Dispatcher) *AtomicDispatcher {
	a := &AtomicDispatcher{}
	a.p.Store(d)
	return a
}

// Get returns the current dispatcher snapshot, or nil if none has been
// installed. The caller is expected to hold the returned pointer for
// the lifetime of a single request — re-calling Get mid-request opens
// a race where the first and second call return different snapshots.
func (a *AtomicDispatcher) Get() *Dispatcher {
	if a == nil {
		return nil
	}
	return a.p.Load()
}

// Store atomically swaps the current dispatcher. Passing nil disables
// dispatch (future [Get] calls return nil until the next Store). The
// old dispatcher (if any) is returned so the caller can inspect it
// for teardown bookkeeping; a nil return means "no prior snapshot".
//
// Store is safe under concurrent Get + Dispatch traffic: each in-flight
// request is already pinned to its own snapshot, so the swap only
// affects requests that have not yet called Get.
func (a *AtomicDispatcher) Store(d *Dispatcher) *Dispatcher {
	if a == nil {
		return nil
	}
	return a.p.Swap(d)
}

// CompareAndSwap is a convenience for reload pipelines that want to
// avoid clobbering a concurrent reload. It returns true when the swap
// succeeded (old == current snapshot). Typical use is an idempotency
// check: "install this policy iff the prior is still the one I
// reconciled against".
func (a *AtomicDispatcher) CompareAndSwap(oldDisp, newDisp *Dispatcher) bool {
	if a == nil {
		return false
	}
	return a.p.CompareAndSwap(oldDisp, newDisp)
}
