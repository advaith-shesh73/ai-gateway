// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// Filter decision labels specific to shadow-mode evaluation and the
// kill-switch short-circuit. These flow into
// mcp_filter_decisions_total{action=...} so operators can chart what
// the filter WOULD have done on real traffic without taking the
// enforcement risk.
//
// Semantics:
//   - contentFilterActionShadowWouldPass:    filter ran, returned pass
//   - contentFilterActionShadowWouldRedact:  filter ran, returned redact
//   - contentFilterActionShadowWouldReject:  filter ran, returned reject
//   - contentFilterActionShadowWouldFail:    filter ran, errored; in
//     enforce mode this would have produced FailedOpen or Unavailable
//     (depending on FailurePolicy). Shadow mode always forwards the
//     original body.
//   - contentFilterActionShadowSampledOut:   sampling budget skipped
//     the filter call; no upstream contact was made.
//   - contentFilterActionDisabled:           kill switch short-circuit;
//     no upstream contact.
//
// These strings are public counter-label values; renaming them breaks
// dashboards and alert rules.
const (
	contentFilterActionShadowWouldPass   = "shadow_would_pass"
	contentFilterActionShadowWouldRedact = "shadow_would_redact"
	contentFilterActionShadowWouldReject = "shadow_would_reject"
	contentFilterActionShadowWouldFail   = "shadow_would_fail"
	contentFilterActionShadowSampledOut  = "shadow_sampled_out"
	contentFilterActionDisabled          = "disabled"
)

// shadowRoll is the per-process source of randomness for shadow-mode
// sampling. It is an atomic pointer so tests can swap in a
// deterministic roller without touching package init.
//
// The default roller reads 4 bytes from crypto/rand per invocation.
// Sampling fires in the hot path so this is wasteful; but 4 bytes on
// Linux is a single getrandom() syscall and the shadow path already
// pays for an LLM round-trip when it passes the gate. Optimising the
// roller is a future concern.
var shadowRoll atomic.Pointer[func() int32]

// rollShadowPermille returns a uniformly-distributed int32 in [0, 1000).
// A call passes the sampling gate when the roll is strictly less than
// the configured rate: rate=1000 always passes, rate=0 never passes,
// rate=250 passes exactly 25 % of the time.
func rollShadowPermille() int32 {
	if fp := shadowRoll.Load(); fp != nil {
		return (*fp)()
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic; treat as "never
		// sample" so an ambient entropy failure cannot leak
		// traffic through the filter unexpectedly. The gateway
		// will also surface the error via its operational logs
		// at the invocation site (see emitShadowDecision
		// callers).
		return 1000
	}
	u := binary.BigEndian.Uint32(b[:])
	// u % 1000 is always in [0,999], so the uint32 -> int32
	// conversion cannot overflow. The #nosec annotation is
	// required because gosec cannot reason about modulo ranges.
	return int32(u % 1000) //nolint:gosec // u%1000 is always <=999, fits in int32.
}

// setShadowRoller installs a deterministic roller for tests. Passing
// nil restores the crypto/rand default. Callers MUST unset (pass nil)
// in test teardown so package-level state does not leak across tests.
func setShadowRoller(fn func() int32) {
	if fn == nil {
		shadowRoll.Store(nil)
		return
	}
	shadowRoll.Store(&fn)
}

// sampleThisShadowCall consults the filter's ShadowSampleRatePermille
// and returns true when this particular invocation passes the gate.
// Enforce-mode filters always pass — sampling enforcement would leak
// data — so the mode check lives here (rather than at the call site)
// to make the contract obvious: the shadow path is the ONLY path that
// can be skipped by sampling.
func (cf *contentFilter) sampleThisShadowCall() bool {
	if cf == nil {
		return true
	}
	if cf.effectiveMode() != filterapi.MCPContentFilterModeShadow {
		return true
	}
	rate := cf.shadowSampleRateBounded()
	if rate >= 1000 {
		return true
	}
	if rate <= 0 {
		return false
	}
	return rollShadowPermille() < rate
}

// shadowBodyVerdict classifies the filter's response in shadow mode so
// the gateway can emit the correct "what WOULD have happened" metric
// and audit outcome without having to apply the verdict.
//
// Inputs match the invoke() return tuple.
func shadowBodyVerdict(originalBody, newBody []byte, rejected bool) string {
	if rejected {
		return contentFilterActionShadowWouldReject
	}
	if bytes.Equal(originalBody, newBody) {
		return contentFilterActionShadowWouldPass
	}
	return contentFilterActionShadowWouldRedact
}

// emitShadowDecision increments mcp_filter_decisions_total with the
// shadow action label when metrics are installed. Safe to call with a
// nil [PrometheusMetrics] (no-op) so tests that don't wire metrics
// still exercise the decision path.
func emitShadowDecision(route filterapi.MCPRouteName, backend filterapi.MCPBackendName, scope Scope, action string) {
	m := filterMetricsLoad()
	if m == nil {
		return
	}
	m.RecordDecision(route, backend, scope, Action(action))
}

// shadowAuditLogger is the package-level audit sink used for
// shadow-mode decision events. Installed via [SetShadowAuditLogger];
// nil means no audit emission (useful in unit tests that assert purely
// on metrics).
//
// The logger is intentionally separate from the PII client's audit
// logger — shadow-mode events have different retention (shorter,
// typically), different access control (SRE + security can see them),
// and different schema expectations. Sharing a sink by default is
// fine; wiring them independently means operators can route them to
// different collectors during an incident.
var shadowAuditLogger atomic.Pointer[RedactionAuditLogger]

// SetShadowAuditLogger installs (or clears when nil) the audit sink
// used to record shadow-mode decisions and kill-switch short-circuits.
// Typically called once during gateway bootstrap, immediately after
// the operational audit logger is wired. Safe to call at any time.
func SetShadowAuditLogger(l RedactionAuditLogger) {
	if l == nil {
		shadowAuditLogger.Store(nil)
		return
	}
	shadowAuditLogger.Store(&l)
}

// shadowAuditLoggerLoad returns the currently-installed logger, or a
// [NoopRedactionAuditLogger] so callers never have to nil-check.
func shadowAuditLoggerLoad() RedactionAuditLogger {
	if lp := shadowAuditLogger.Load(); lp != nil && *lp != nil {
		return *lp
	}
	return NoopRedactionAuditLogger{}
}

// emitShadowAudit writes a RedactionAuditEvent with the shadow-mode
// outcome. inputChars and outputChars track the body sizes so
// dashboards can compare shadow-mode redaction rate against
// enforce-mode without replaying content. reason is the free-form
// string returned by the filter (used for redact/reject); elapsed is
// the filter round-trip time (0 for sampled-out and disabled paths).
func emitShadowAudit(
	ctx context.Context,
	route filterapi.MCPRouteName,
	backend filterapi.MCPBackendName,
	tool string,
	action string,
	reason string,
	inputChars, outputChars int,
	elapsed time.Duration,
) {
	logger := shadowAuditLoggerLoad()
	ev := &RedactionAuditEvent{
		Timestamp:   time.Now().UTC(),
		Route:       route,
		Backend:     backend,
		Tool:        tool,
		PIIContext:  "content_filter:shadow",
		InputChars:  inputChars,
		OutputChars: outputChars,
		Elapsed:     elapsed,
		Outcome:     action,
		// Shadow mode by definition does not scrub — the client
		// always sees the original body. Flag it on every event
		// so compliance tooling can distinguish shadow from
		// enforce audit trails with a single field filter.
		FailOpen: true,
	}
	if reason != "" {
		// The Stats map is the only string-keyed field on
		// RedactionAuditEvent that survives the slog JSON
		// handler verbatim. Reusing it for the filter's "why"
		// keeps the audit envelope stable while still
		// surfacing the LLM's reason to downstream consumers.
		ev.Stats = map[string]int{reason: 1}
	}
	logger.LogRedaction(ctx, ev)
}
