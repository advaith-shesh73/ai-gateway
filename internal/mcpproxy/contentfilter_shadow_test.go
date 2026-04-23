// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// The tests in this file cover the shadow-mode, sampling-gate, and
// kill-switch extensions to the dispatcher. They are deliberately
// separate from contentfilter_test.go so the shadow-specific machinery
// (roller installation, audit collector) lives next to the
// contentfilter_shadow.go source file it exercises.

// recordingAuditLogger is a minimal in-memory RedactionAuditLogger
// that captures every event emitted during a test. Used to assert on
// the per-invocation audit trail that shadow mode produces.
type recordingAuditLogger struct {
	events []*RedactionAuditEvent
}

func (r *recordingAuditLogger) LogRedaction(_ context.Context, ev *RedactionAuditEvent) {
	// Deep-copy the caller's event because the contract says callers
	// MUST NOT retain ev beyond the call — we make the copy here.
	cp := *ev
	r.events = append(r.events, &cp)
}

// withRecordingAudit installs a recording audit logger for the
// duration of a test and returns (a) the logger instance so callers
// can inspect events and (b) a cleanup func to defer.
func withRecordingAudit(t *testing.T) (*recordingAuditLogger, func()) {
	t.Helper()
	rec := &recordingAuditLogger{}
	SetShadowAuditLogger(rec)
	return rec, func() { SetShadowAuditLogger(nil) }
}

// deterministicRoller returns a roller that yields the given value on
// every call. Use with setShadowRoller to make sampling deterministic.
func deterministicRoller(v int32) func() int32 { return func() int32 { return v } }

// counterRoller returns a roller that cycles through values. Useful
// when a test needs to exercise both "sampled in" and "sampled out"
// branches in one run.
func counterRoller(values ...int32) func() int32 {
	var i int64
	return func() int32 {
		idx := atomic.AddInt64(&i, 1) - 1
		return values[idx%int64(len(values))]
	}
}

// newShadowFilter returns a compiled filter pointed at serverURL with
// the given shadow rate in permille. Scopes default to both request
// and response so each test can pick.
func newShadowFilter(t *testing.T, serverURL string, rate int32) *contentFilter {
	t.Helper()
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL: serverURL,
		Scopes: []filterapi.MCPContentFilterScope{
			filterapi.MCPContentFilterScopeRequest,
			filterapi.MCPContentFilterScopeResponse,
		},
		TimeoutSeconds:           1,
		Mode:                     filterapi.MCPContentFilterModeShadow,
		ShadowSampleRatePermille: rate,
	}, "r", "b")
	require.NoError(t, err)
	return cf
}

// --- isDisabled ------------------------------------------------------------

func TestContentFilter_IsDisabled_NilReceiverIsEnabled(t *testing.T) {
	var cf *contentFilter
	require.False(t, cf.isDisabled(),
		"nil receiver should never be considered disabled")
}

func TestContentFilter_IsDisabled_GlobalDisableTrumpsEverything(t *testing.T) {
	enabled := true
	cf := &contentFilter{
		enabled: &enabled, // per-backend says on
		policy:  &filterapi.MCPContentFilterPolicyConfig{GlobalDisable: true},
	}
	require.True(t, cf.isDisabled(),
		"GlobalDisable must short-circuit even when the per-backend Enabled flag is true")
}

func TestContentFilter_IsDisabled_PerBackendEnabledFalseDisables(t *testing.T) {
	disabled := false
	cf := &contentFilter{enabled: &disabled}
	require.True(t, cf.isDisabled())
}

func TestContentFilter_IsDisabled_PerBackendEnabledNilTreatedAsEnabled(t *testing.T) {
	cf := &contentFilter{enabled: nil}
	require.False(t, cf.isDisabled(),
		"a nil Enabled pointer means 'no opinion', which must default to enabled so configs that predate the flag keep working")
}

// --- effectiveMode ---------------------------------------------------------

func TestContentFilter_EffectiveMode_DefaultsToEnforce(t *testing.T) {
	var cf *contentFilter
	require.Equal(t, filterapi.MCPContentFilterModeEnforce, cf.effectiveMode())

	cf = &contentFilter{}
	require.Equal(t, filterapi.MCPContentFilterModeEnforce, cf.effectiveMode())
}

func TestContentFilter_EffectiveMode_PreservesExplicitShadow(t *testing.T) {
	cf := &contentFilter{mode: filterapi.MCPContentFilterModeShadow}
	require.Equal(t, filterapi.MCPContentFilterModeShadow, cf.effectiveMode())
}

// --- shadowSampleRateBounded ----------------------------------------------

func TestShadowSampleRateBounded_ZeroTreatedAsFullySampled(t *testing.T) {
	cf := &contentFilter{shadowSampleRatePermille: 0}
	require.Equal(t, int32(1000), cf.shadowSampleRateBounded(),
		"zero is the zero-value; back-compat configs must keep running at 100%")
}

func TestShadowSampleRateBounded_ClampsHighValues(t *testing.T) {
	cf := &contentFilter{shadowSampleRatePermille: 9999}
	require.Equal(t, int32(1000), cf.shadowSampleRateBounded(),
		"values above 1000 clamp to 1000 — there is no 'super sampled' rate")
}

func TestShadowSampleRateBounded_PreservesInRange(t *testing.T) {
	cf := &contentFilter{shadowSampleRatePermille: 250}
	require.Equal(t, int32(250), cf.shadowSampleRateBounded())
}

// --- sampleThisShadowCall --------------------------------------------------

func TestSampleThisShadowCall_EnforceModeAlwaysPasses(t *testing.T) {
	// Enforce-mode filters must NEVER be skipped by sampling: that
	// would let data leak. The gate belongs to the shadow path.
	cf := &contentFilter{
		mode:                     filterapi.MCPContentFilterModeEnforce,
		shadowSampleRatePermille: 0,
	}
	setShadowRoller(deterministicRoller(999))
	defer setShadowRoller(nil)
	require.True(t, cf.sampleThisShadowCall())
}

func TestSampleThisShadowCall_Rate1000AlwaysPasses(t *testing.T) {
	cf := &contentFilter{mode: filterapi.MCPContentFilterModeShadow, shadowSampleRatePermille: 1000}
	// Roll 999 (largest possible value) must still pass because the
	// gate is strictly less-than: 999 < 1000 passes.
	setShadowRoller(deterministicRoller(999))
	defer setShadowRoller(nil)
	require.True(t, cf.sampleThisShadowCall())
}

func TestSampleThisShadowCall_LowRateMostlyFails(t *testing.T) {
	cf := &contentFilter{mode: filterapi.MCPContentFilterModeShadow, shadowSampleRatePermille: 10}
	setShadowRoller(deterministicRoller(999))
	defer setShadowRoller(nil)
	require.False(t, cf.sampleThisShadowCall(),
		"rate=10, roll=999 -> 999 >= 10 -> gate skips")
}

func TestSampleThisShadowCall_LowRateOccasionallyPasses(t *testing.T) {
	cf := &contentFilter{mode: filterapi.MCPContentFilterModeShadow, shadowSampleRatePermille: 10}
	setShadowRoller(deterministicRoller(5))
	defer setShadowRoller(nil)
	require.True(t, cf.sampleThisShadowCall(),
		"rate=10, roll=5 -> 5 < 10 -> gate passes")
}

// --- shadowBodyVerdict -----------------------------------------------------

func TestShadowBodyVerdict_RejectedTrumpsBodyEquality(t *testing.T) {
	same := []byte("{}")
	require.Equal(t, contentFilterActionShadowWouldReject,
		shadowBodyVerdict(same, same, true))
}

func TestShadowBodyVerdict_PassOnBodyEquality(t *testing.T) {
	b := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	require.Equal(t, contentFilterActionShadowWouldPass,
		shadowBodyVerdict(b, b, false))
}

func TestShadowBodyVerdict_RedactOnBodyDifference(t *testing.T) {
	require.Equal(t, contentFilterActionShadowWouldRedact,
		shadowBodyVerdict([]byte("a"), []byte("b"), false))
}

// --- apply*: kill-switch short-circuit ------------------------------------

// A content filter whose GlobalDisable policy is set MUST NOT contact
// the upstream filter service. We prove that by pointing the filter at
// an httptest server that fatally fails the test if touched.
func TestApplyOnRequest_KillSwitchGlobalDisable_SkipsUpstream(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must never be contacted when the kill switch is engaged")
	}))
	defer srv.Close()

	cf := newTestFilter(t, srv.URL, false)
	cf.policy = &filterapi.MCPContentFilterPolicyConfig{GlobalDisable: true}

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got,
		"disabled path forwards the original request pointer verbatim")
	require.Equal(t, FilterStatusDisabled, status)

	require.Len(t, rec.events, 1,
		"kill-switch short-circuit must still emit exactly one audit event for visibility")
	ev := rec.events[0]
	require.Equal(t, contentFilterActionDisabled, ev.Outcome)
	require.Equal(t, 0, ev.InputChars,
		"disabled path did not inspect the body so sizes are zero")
	require.True(t, ev.FailOpen,
		"disabled events must be flagged FailOpen=true because no scrub occurred")
}

func TestApplyOnResponse_KillSwitchPerBackendEnabledFalse_SkipsUpstream(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must never be contacted when Enabled=false")
	}))
	defer srv.Close()

	cf := newTestFilter(t, srv.URL, false)
	off := false
	cf.enabled = &off

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, status, err := applyContentFilterOnResponseWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, FilterStatusDisabled, status)

	require.Len(t, rec.events, 1)
	require.Equal(t, contentFilterActionDisabled, rec.events[0].Outcome)
}

// --- apply*: shadow sampling gate -----------------------------------------

func TestApplyOnRequest_ShadowSamplingGate_SampledOutSkipsUpstream(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("sampled-out shadow calls must not touch the upstream filter")
	}))
	defer srv.Close()

	cf := newShadowFilter(t, srv.URL, 10 /* 1% */)
	// Roll 999: 999 >= 10, so we skip the filter.
	setShadowRoller(deterministicRoller(999))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got)
	// Shadow mode never reports FilterStatusDisabled for the
	// sampling path — the filter IS configured and active, it
	// simply chose not to run for this invocation.
	require.Equal(t, FilterStatusPass, status)

	require.Len(t, rec.events, 1)
	require.Equal(t, contentFilterActionShadowSampledOut, rec.events[0].Outcome)
}

func TestApplyOnResponse_ShadowSamplingGate_SampledInHitsUpstream(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	var hits int32
	replacement := []byte(`{"jsonrpc":"2.0","id":1,"result":{"scrubbed":true}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action:     contentFilterActionRedact,
			BodyBase64: base64.StdEncoding.EncodeToString(replacement),
			Reason:     "would-scrub-this",
		})
	}))
	defer srv.Close()

	cf := newShadowFilter(t, srv.URL, 1000 /* 100% */)
	setShadowRoller(deterministicRoller(0))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"secret": "leaked"})}
	got, status, err := applyContentFilterOnResponseWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got,
		"shadow mode must forward the ORIGINAL response even when the filter said redact")
	require.Equal(t, FilterStatusPass, status)

	require.Equal(t, int32(1), atomic.LoadInt32(&hits),
		"sampled-in shadow call must consult the upstream filter exactly once")

	// Shadow audit: one event, outcome=would_redact, includes
	// the reason the filter returned.
	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	require.Equal(t, contentFilterActionShadowWouldRedact, ev.Outcome)
	require.NotZero(t, ev.InputChars, "shadow audits must carry the input size")
	require.NotZero(t, ev.OutputChars, "shadow audits must carry the would-redact output size")
	require.Contains(t, ev.Stats, "would-scrub-this",
		"the filter's reason must travel with the shadow audit so SRE can review it offline")
}

// --- apply*: shadow upstream outcomes --------------------------------------

func TestApplyOnRequest_ShadowMode_UpstreamRejectClassifiedAsWouldReject(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action: contentFilterActionReject,
			Reason: "would-block-this",
		})
	}))
	defer srv.Close()

	cf := newShadowFilter(t, srv.URL, 1000)
	setShadowRoller(deterministicRoller(0))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err,
		"shadow mode must never surface reject as an error — it only records what WOULD have happened")
	require.Same(t, req, got)
	require.Equal(t, FilterStatusPass, status)

	require.Len(t, rec.events, 1)
	require.Equal(t, contentFilterActionShadowWouldReject, rec.events[0].Outcome)
}

func TestApplyOnRequest_ShadowMode_UpstreamErrorClassifiedAsWouldFail(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	// Unreachable: connection is refused immediately.
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:                      "http://127.0.0.1:1",
		Scopes:                   []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		TimeoutSeconds:           1,
		Mode:                     filterapi.MCPContentFilterModeShadow,
		ShadowSampleRatePermille: 1000,
	}, "r", "b")
	require.NoError(t, err)

	setShadowRoller(deterministicRoller(0))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err,
		"shadow mode must never surface upstream errors — filter outages during rollout must NOT affect traffic")
	require.Same(t, req, got)
	require.Equal(t, FilterStatusPass, status)

	require.Len(t, rec.events, 1)
	require.Equal(t, contentFilterActionShadowWouldFail, rec.events[0].Outcome)
}

func TestApplyOnResponse_ShadowMode_UpstreamPassClassifiedAsWouldPass(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()

	cf := newShadowFilter(t, srv.URL, 1000)
	setShadowRoller(deterministicRoller(0))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, status, err := applyContentFilterOnResponseWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, FilterStatusPass, status)

	require.Len(t, rec.events, 1)
	require.Equal(t, contentFilterActionShadowWouldPass, rec.events[0].Outcome)
}

// --- apply*: shadow precedence over kill-switch ----------------------------

// Kill switch MUST win over shadow mode: a disabled filter doesn't
// even roll the sampling gate. This test proves the two gates are
// ordered correctly.
func TestApplyOnRequest_DisabledBeatsShadowSampling(t *testing.T) {
	rec, cleanup := withRecordingAudit(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("disabled filter must never contact upstream, even in shadow mode")
	}))
	defer srv.Close()

	cf := newShadowFilter(t, srv.URL, 1000)
	off := false
	cf.enabled = &off

	// Deliberately choose a roller that WOULD sample in, so a wrong
	// ordering of the gates would cause us to hit the upstream.
	setShadowRoller(deterministicRoller(0))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got)
	require.Equal(t, FilterStatusDisabled, status,
		"disabled must be reported even when the filter is in shadow mode")

	require.Len(t, rec.events, 1)
	require.Equal(t, contentFilterActionDisabled, rec.events[0].Outcome,
		"disabled must be recorded — NOT shadow_sampled_out")
}

// --- apply*: enforce mode still behaves as before --------------------------

// A sanity check: sampling and shadow logic must not affect enforce-mode
// filters at all. This guards against future refactors accidentally
// routing enforce traffic through the shadow gate.
func TestApplyOnResponse_EnforceMode_IgnoresSamplingRate(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()

	// Enforce mode + rate=0: the sample-rate field is meaningless
	// for enforce, but we assert the gate is skipped altogether.
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:                      srv.URL,
		Scopes:                   []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeResponse},
		TimeoutSeconds:           1,
		Mode:                     filterapi.MCPContentFilterModeEnforce,
		ShadowSampleRatePermille: 0,
	}, "r", "b")
	require.NoError(t, err)

	setShadowRoller(deterministicRoller(999))
	defer setShadowRoller(nil)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, status, err := applyContentFilterOnResponseWithStatus(context.Background(),
		&mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, FilterStatusPass, status)
	require.Equal(t, int32(1), atomic.LoadInt32(&hits),
		"enforce mode must hit the upstream regardless of sampling rate — sampling is only for shadow")
}

// --- rollShadowPermille: the default-roller contract ----------------------

// The default roller uses crypto/rand; we cannot assert on its exact
// output but we CAN assert that uninstalled test overrides do not
// leak into subsequent tests. This test runs after setShadowRoller is
// restored and exercises the underlying crypto/rand path.
func TestRollShadowPermille_DefaultRangeInvariants(t *testing.T) {
	// Belt-and-braces: ensure no test roller is installed.
	setShadowRoller(nil)

	for i := 0; i < 64; i++ {
		v := rollShadowPermille()
		require.GreaterOrEqual(t, v, int32(0),
			"roll must be non-negative")
		require.Less(t, v, int32(1000),
			"roll must be strictly less than 1000 — otherwise rate=1000 would never hit the gate")
	}
}

// --- counterRoller: covers both branches in one test ----------------------

// Verify a cycle of rolls takes us through "sampled out" and
// "sampled in" branches deterministically — used as a smoke test for
// the roller helper itself.
func TestCounterRoller_CyclesThroughValues(t *testing.T) {
	r := counterRoller(10, 990)
	require.Equal(t, int32(10), r())
	require.Equal(t, int32(990), r())
	require.Equal(t, int32(10), r())
	require.Equal(t, int32(990), r())
}
