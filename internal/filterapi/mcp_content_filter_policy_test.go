// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// newValidPolicy returns a minimal well-formed MCPContentFilterPolicy for
// tests that want to mutate one field at a time and verify the rule that
// trips.
func newValidPolicy() MCPContentFilterPolicy {
	p := MCPContentFilterPolicy{
		Backends: BackendPolicy{
			EnableSupportGPT: true,
			EnableNuRAG:      true,
			EnableGlean:      true,
			EnableDefaultPII: true,
		},
		Cache:   CachePolicy{Enabled: true},
		Breaker: BreakerPolicy{Enabled: true},
	}
	p.ApplyDefaults()
	return p
}

// TestApplyDefaults_FillsZeroValues asserts every documented default is
// installed when the caller passes a zero-value policy.
func TestApplyDefaults_FillsZeroValues(t *testing.T) {
	var p MCPContentFilterPolicy
	p.ApplyDefaults()

	require.Equal(t, defaultPIIServiceURL, p.PII.URL)
	require.Equal(t, float64(60), p.PII.TimeoutSeconds)
	require.Equal(t, 40000, p.PII.MaxCharsPerRequest)
	require.Equal(t, 4, p.PII.MaxParallelChunks)
	require.Equal(t, 4, p.PII.MaxParallelParts)
	require.Equal(t, 100, p.PII.HTTPMaxConnections)
	require.Equal(t, 20, p.PII.HTTPMaxIdle)

	require.Equal(t, 2048, p.Cache.MaxEntries)
	require.Equal(t, float64(900), p.Cache.TTLSeconds)

	require.Equal(t, 10, p.Breaker.FailureThreshold)
	// BreakerResetSeconds defaults to max(30, 2 * PII.TimeoutSeconds) so
	// the default policy passes the cross-field rule Validate() enforces.
	// With PII.TimeoutSeconds=60 the effective default is 120.
	require.Equal(t, float64(120), p.Breaker.ResetSeconds)

	require.Equal(t, float64(15), p.Jira.TimeoutSeconds)
	require.Equal(t, 20, p.Jira.HTTPMaxConnections)
	require.Equal(t, 10, p.Jira.HTTPMaxIdle)
	require.Equal(t, 5, p.Jira.BreakerFailureThreshold)
	require.Equal(t, float64(30), p.Jira.BreakerResetSeconds)

	require.Equal(t, []string{"supportgpt"}, p.Backends.SupportGPTBackendNames)
	require.Equal(t, []string{"nurag"}, p.Backends.NuRAGBackendNames)
	require.Equal(t, []string{"glean"}, p.Backends.GleanBackendNames)
	require.Equal(t, []string{"atlassian", "jira"}, p.Backends.JiraBackendNames)
	require.ElementsMatch(t, defaultPIIScanBackends, p.Backends.PIIScanBackends)

	require.Equal(t, "x-eval-exclude-ticket-id", p.Eval.Name)
	require.Equal(t, int64(2<<20), p.Wire.MaxBodyBytes)
}

// TestApplyDefaults_IsIdempotent asserts that calling ApplyDefaults twice
// produces identical output (and, crucially, does not overwrite operator-set
// values on the second pass).
func TestApplyDefaults_IsIdempotent(t *testing.T) {
	p := newValidPolicy()
	original, err := json.Marshal(p)
	require.NoError(t, err)

	p.ApplyDefaults()
	got, err := json.Marshal(p)
	require.NoError(t, err)

	require.JSONEq(t, string(original), string(got))
}

// TestApplyDefaults_PreservesOperatorValues asserts an explicitly-set field
// survives the defaulting pass. A zero check against the default would
// incorrectly reset an operator choice; this guards against that regression.
func TestApplyDefaults_PreservesOperatorValues(t *testing.T) {
	p := MCPContentFilterPolicy{
		PII: PIIPolicy{
			URL:                "http://custom.example/anonymize",
			TimeoutSeconds:     123,
			MaxCharsPerRequest: 9999,
			MaxParallelChunks:  2,
			MaxParallelParts:   2,
			HTTPMaxConnections: 50,
			HTTPMaxIdle:        5,
		},
		Backends: BackendPolicy{EnableDefaultPII: true},
		Cache:    CachePolicy{Enabled: true},
		Breaker:  BreakerPolicy{Enabled: true},
	}
	p.ApplyDefaults()

	require.Equal(t, "http://custom.example/anonymize", p.PII.URL)
	require.Equal(t, float64(123), p.PII.TimeoutSeconds)
	require.Equal(t, 9999, p.PII.MaxCharsPerRequest)
	require.Equal(t, 2, p.PII.MaxParallelChunks)
	require.Equal(t, 2, p.PII.MaxParallelParts)
	require.Equal(t, 50, p.PII.HTTPMaxConnections)
	require.Equal(t, 5, p.PII.HTTPMaxIdle)
}

// TestDefaultMCPContentFilterPolicy_IsValid asserts the convenience factory
// returns a policy that passes Validate() out of the box.
func TestDefaultMCPContentFilterPolicy_IsValid(t *testing.T) {
	p := DefaultMCPContentFilterPolicy()
	require.NoError(t, p.Validate())
}

// TestValidate_NilPolicy asserts that calling Validate on a nil receiver
// returns an error rather than panicking.
func TestValidate_NilPolicy(t *testing.T) {
	var p *MCPContentFilterPolicy
	err := p.Validate()
	require.Error(t, err)
	var pve *PolicyValidationError
	require.ErrorAs(t, err, &pve)
	require.Equal(t, ReasonPolicyMismatch, pve.Reason)
}

// TestValidate_RequirePIIFailClosed asserts the load-bearing binding rule:
// RequirePIIFailClosed=true forces FailClosed=true on PII. This is the Jeff
// Dean P0 #5 fix — the reconciler is the sole enforcement point now that
// env-var binding is gone.
func TestValidate_RequirePIIFailClosed(t *testing.T) {
	t.Run("require_true_fail_closed_true_passes", func(t *testing.T) {
		p := newValidPolicy()
		p.RequirePIIFailClosed = true
		p.PII.FailClosed = true
		require.NoError(t, p.Validate())
	})

	t.Run("require_true_fail_closed_false_fails_with_PolicyMismatch", func(t *testing.T) {
		p := newValidPolicy()
		p.RequirePIIFailClosed = true
		p.PII.FailClosed = false
		err := p.Validate()
		require.Error(t, err)
		require.True(t, IsPolicyValidationError(err))
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonPolicyMismatch, pve.Reason)
		require.Equal(t, "pii.failClosed", pve.Field)
	})

	t.Run("require_false_fail_closed_false_passes", func(t *testing.T) {
		p := newValidPolicy()
		p.RequirePIIFailClosed = false
		p.PII.FailClosed = false
		require.NoError(t, p.Validate())
	})
}

// TestValidate_PIIURL asserts all URL-level failure modes produce
// PIIURLInvalid with the URL field pointed out.
func TestValidate_PIIURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"empty", "", "required"},
		{"invalid", "://not-a-url", "not a valid URL"},
		{"wrong-scheme", "ftp://host/path", "scheme"},
		{"missing-host", "http:///path", "host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newValidPolicy()
			p.PII.URL = tc.url
			err := p.Validate()
			require.Error(t, err)
			var pve *PolicyValidationError
			require.ErrorAs(t, err, &pve)
			require.Equal(t, ReasonPIIURLInvalid, pve.Reason)
			require.Contains(t, pve.Message, tc.want)
		})
	}

	t.Run("accepts_http", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.URL = "http://pii/anonymize"
		require.NoError(t, p.Validate())
	})

	t.Run("accepts_https", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.URL = "https://pii.example/anonymize"
		require.NoError(t, p.Validate())
	})
}

// TestValidate_PIITimeout asserts TimeoutSeconds <= 0 is rejected. Python
// refuses to start; Go reconciler does the same.
func TestValidate_PIITimeout(t *testing.T) {
	for _, v := range []float64{0, -1, -0.001} {
		p := newValidPolicy()
		p.PII.TimeoutSeconds = v
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonTimeoutInvalid, pve.Reason)
	}
}

// TestValidate_PIIMaxChars asserts Rule #3 (MaxCharsPerRequest >= 1024) and
// its error classification.
func TestValidate_PIIMaxChars(t *testing.T) {
	t.Run("below_minimum_rejected", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.MaxCharsPerRequest = 1023
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonPIIMaxCharsTooSmall, pve.Reason)
	})

	t.Run("equal_to_minimum_accepted", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.MaxCharsPerRequest = 1024
		require.NoError(t, p.Validate())
	})

	t.Run("zero_rejected_after_defaults_because_explicit_override", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.MaxCharsPerRequest = 0
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonPIIMaxCharsTooSmall, pve.Reason)
	})
}

// TestValidate_Parallelism asserts Rule #4: both parts and chunks limits
// must lie in [1, 32].
func TestValidate_Parallelism(t *testing.T) {
	cases := []struct {
		name       string
		parts      int
		chunks     int
		wantReason string
	}{
		{"parts_zero", 0, 4, ReasonParallelismOutOfBounds},
		{"parts_negative", -1, 4, ReasonParallelismOutOfBounds},
		{"parts_above_max", 33, 4, ReasonParallelismOutOfBounds},
		{"chunks_zero", 4, 0, ReasonParallelismOutOfBounds},
		{"chunks_negative", 4, -1, ReasonParallelismOutOfBounds},
		{"chunks_above_max", 4, 33, ReasonParallelismOutOfBounds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newValidPolicy()
			p.PII.MaxParallelParts = tc.parts
			p.PII.MaxParallelChunks = tc.chunks
			err := p.Validate()
			require.Error(t, err)
			var pve *PolicyValidationError
			require.ErrorAs(t, err, &pve)
			require.Equal(t, tc.wantReason, pve.Reason)
		})
	}

	for _, pair := range [][2]int{{1, 1}, {32, 32}, {16, 8}} {
		t.Run("bounds_ok", func(t *testing.T) {
			p := newValidPolicy()
			p.PII.MaxParallelParts = pair[0]
			p.PII.MaxParallelChunks = pair[1]
			require.NoError(t, p.Validate())
		})
	}
}

// TestValidate_JiraCreds asserts Rule #9: enabling the Jira handler requires
// BaseURL, Email, and at least one credential source.
func TestValidate_JiraCreds(t *testing.T) {
	base := func() MCPContentFilterPolicy {
		p := newValidPolicy()
		p.Backends.EnableJira = true
		p.Jira.BaseURL = "https://jira.example/"
		p.Jira.Email = "filter-bot@example.com"
		p.Jira.APITokenFromEnv = "AIGWCF_JIRA_API_TOKEN"
		return p
	}

	t.Run("fully_configured_passes", func(t *testing.T) {
		p := base()
		require.NoError(t, p.Validate())
	})

	t.Run("missing_baseURL_fails", func(t *testing.T) {
		p := base()
		p.Jira.BaseURL = ""
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonJiraEnabledButNoCreds, pve.Reason)
	})

	t.Run("missing_email_fails", func(t *testing.T) {
		p := base()
		p.Jira.Email = ""
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonJiraEnabledButNoCreds, pve.Reason)
	})

	t.Run("missing_both_credentials_fails", func(t *testing.T) {
		p := base()
		p.Jira.APITokenFromEnv = ""
		p.Jira.APITokenFile = ""
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonJiraEnabledButNoCreds, pve.Reason)
	})

	t.Run("file_credential_alone_passes", func(t *testing.T) {
		p := base()
		p.Jira.APITokenFromEnv = ""
		p.Jira.APITokenFile = "/var/run/secrets/jira-token"
		require.NoError(t, p.Validate())
	})

	t.Run("disabled_jira_ignores_missing_creds", func(t *testing.T) {
		p := newValidPolicy()
		p.Backends.EnableJira = false
		require.NoError(t, p.Validate())
	})
}

// TestValidate_JiraTimeout asserts Jira timeout is checked only when the
// handler is enabled.
func TestValidate_JiraTimeout(t *testing.T) {
	t.Run("disabled_allows_zero", func(t *testing.T) {
		p := newValidPolicy()
		p.Backends.EnableJira = false
		p.Jira.TimeoutSeconds = 0
		require.NoError(t, p.Validate())
	})

	t.Run("enabled_zero_rejected", func(t *testing.T) {
		p := newValidPolicy()
		p.Backends.EnableJira = true
		p.Jira.BaseURL = "https://jira/"
		p.Jira.Email = "bot@example.com"
		p.Jira.APITokenFromEnv = "TOK"
		p.Jira.TimeoutSeconds = 0
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonTimeoutInvalid, pve.Reason)
	})
}

// TestValidate_CacheTTL asserts Rule #6: cache TTL must outlive in-flight
// PII calls. Skipped when cache disabled.
func TestValidate_CacheTTL(t *testing.T) {
	t.Run("ttl_shorter_than_timeout_rejected", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.TimeoutSeconds = 60
		p.Cache.TTLSeconds = 30
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonCacheTTLTooShort, pve.Reason)
	})

	t.Run("ttl_equal_to_timeout_accepted", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.TimeoutSeconds = 60
		p.Cache.TTLSeconds = 60
		require.NoError(t, p.Validate())
	})

	t.Run("cache_disabled_skips_check", func(t *testing.T) {
		p := newValidPolicy()
		p.Cache.Enabled = false
		p.Cache.TTLSeconds = 1
		p.PII.TimeoutSeconds = 60
		require.NoError(t, p.Validate())
	})
}

// TestValidate_BreakerReset asserts Rule #7: Breaker.ResetSeconds must be
// >= 2x PII.TimeoutSeconds. Skipped when breaker disabled.
func TestValidate_BreakerReset(t *testing.T) {
	t.Run("reset_too_short_rejected", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.TimeoutSeconds = 60
		p.Breaker.ResetSeconds = 60 // needs 120
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonBreakerResetTooShort, pve.Reason)
	})

	t.Run("reset_equal_to_2x_accepted", func(t *testing.T) {
		p := newValidPolicy()
		p.PII.TimeoutSeconds = 60
		p.Breaker.ResetSeconds = 120
		require.NoError(t, p.Validate())
	})

	t.Run("breaker_disabled_skips_check", func(t *testing.T) {
		p := newValidPolicy()
		p.Breaker.Enabled = false
		p.Breaker.ResetSeconds = 1
		p.PII.TimeoutSeconds = 60
		require.NoError(t, p.Validate())
	})
}

// TestValidate_WireLimits asserts Rule #5 bounds [64 KiB, 64 MiB].
func TestValidate_WireLimits(t *testing.T) {
	cases := []struct {
		name  string
		bytes int64
		ok    bool
	}{
		{"below_min", (64 << 10) - 1, false},
		{"at_min", 64 << 10, true},
		{"typical_2MiB", 2 << 20, true},
		{"at_max", 64 << 20, true},
		{"above_max", (64 << 20) + 1, false},
		{"zero", 0, false},
		{"negative", -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newValidPolicy()
			p.Wire.MaxBodyBytes = tc.bytes
			err := p.Validate()
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				var pve *PolicyValidationError
				require.ErrorAs(t, err, &pve)
				require.Equal(t, ReasonBodyCapOutOfBounds, pve.Reason)
			}
		})
	}
}

// TestValidate_EvalHeaderStrict asserts strict-mode requires a non-empty
// header name.
func TestValidate_EvalHeaderStrict(t *testing.T) {
	t.Run("strict_without_name_rejected", func(t *testing.T) {
		p := newValidPolicy()
		p.Eval.Name = ""
		p.Eval.Strict = true
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonEvalStrictWithoutHeader, pve.Reason)
	})

	t.Run("strict_with_whitespace_only_name_rejected", func(t *testing.T) {
		p := newValidPolicy()
		p.Eval.Name = "   "
		p.Eval.Strict = true
		err := p.Validate()
		require.Error(t, err)
		var pve *PolicyValidationError
		require.ErrorAs(t, err, &pve)
		require.Equal(t, ReasonEvalStrictWithoutHeader, pve.Reason)
	})

	t.Run("strict_with_name_accepted", func(t *testing.T) {
		p := newValidPolicy()
		p.Eval.Strict = true
		require.NoError(t, p.Validate())
	})

	t.Run("non_strict_with_empty_name_accepted", func(t *testing.T) {
		p := newValidPolicy()
		p.Eval.Name = ""
		p.Eval.Strict = false
		require.NoError(t, p.Validate())
	})
}

// TestValidate_AtLeastOneBackendEnabled asserts Rule #finalized: the policy
// must enable at least one handler.
func TestValidate_AtLeastOneBackendEnabled(t *testing.T) {
	p := newValidPolicy()
	p.Backends.EnableSupportGPT = false
	p.Backends.EnableNuRAG = false
	p.Backends.EnableGlean = false
	p.Backends.EnableJira = false
	p.Backends.EnableDefaultPII = false
	err := p.Validate()
	require.Error(t, err)
	var pve *PolicyValidationError
	require.ErrorAs(t, err, &pve)
	require.Equal(t, ReasonNoBackendsEnabled, pve.Reason)
}

// TestValidateAll_ReturnsAllViolations asserts ValidateAll surfaces every
// rule failure at once (for the reconciler's admission report).
func TestValidateAll_ReturnsAllViolations(t *testing.T) {
	p := newValidPolicy()
	p.PII.TimeoutSeconds = -1      // rule: TimeoutInvalid
	p.PII.MaxCharsPerRequest = 500 // rule: PIIMaxCharsTooSmall
	p.PII.MaxParallelParts = 0     // rule: ParallelismOutOfBounds
	p.Cache.TTLSeconds = 1         // rule: CacheTTLTooShort (but PII timeout is -1 so noop effectively)
	p.Breaker.ResetSeconds = 1     // rule: BreakerResetTooShort
	p.Wire.MaxBodyBytes = 1        // rule: BodyCapOutOfBounds
	p.Eval.Name = ""               // with strict, rule: EvalStrictWithoutHeader
	p.Eval.Strict = true

	errs := p.ValidateAll()
	require.NotEmpty(t, errs)
	// We expect at least five distinct reasons to surface.
	reasons := map[string]bool{}
	for _, e := range errs {
		reasons[e.Reason] = true
	}
	require.GreaterOrEqual(t, len(reasons), 5,
		"expected ValidateAll to surface multiple rule violations, got %v", reasons)
}

// TestIsPolicyValidationError asserts the helper discriminates correctly.
func TestIsPolicyValidationError(t *testing.T) {
	pve := &PolicyValidationError{Reason: "x", Message: "y"}
	require.True(t, IsPolicyValidationError(pve))
	require.False(t, IsPolicyValidationError(nil))
	// errors.New is a plain error, not a PolicyValidationError
	require.False(t, IsPolicyValidationError(errNotPolicy))
}

// errNotPolicy is declared as a package-level var so it doesn't create a
// new object every call; keeps TestIsPolicyValidationError cheap and clear.
var errNotPolicy = &sentinelError{msg: "unrelated error"}

type sentinelError struct{ msg string }

func (e *sentinelError) Error() string { return e.msg }

// TestPolicyValidationError_Error asserts the formatter produces a stable
// string shape that reconciler logs grep on.
func TestPolicyValidationError_Error(t *testing.T) {
	pve := &PolicyValidationError{
		Reason:  "X",
		Message: "bad",
		Field:   "a.b",
	}
	s := pve.Error()
	require.Contains(t, s, "X:")
	require.Contains(t, s, "bad")
	require.Contains(t, s, "a.b")

	pveNoField := &PolicyValidationError{Reason: "X", Message: "bad"}
	require.NotContains(t, pveNoField.Error(), "field=")
	require.True(t, strings.HasPrefix(pveNoField.Error(), "X:"))
}

// TestPolicy_CrossFieldValidation is the named test from HANDOFF §6.5 that
// enumerates each rule with passing and failing inputs. Serves as a single
// lookup table for operators debugging a PolicyMismatch alert.
func TestPolicy_CrossFieldValidation(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*MCPContentFilterPolicy)
		wantReason string
	}{
		{
			name: "rule1_policy_mismatch",
			mutate: func(p *MCPContentFilterPolicy) {
				p.RequirePIIFailClosed = true
				p.PII.FailClosed = false
			},
			wantReason: ReasonPolicyMismatch,
		},
		{
			name:       "rule3_pii_max_chars_too_small",
			mutate:     func(p *MCPContentFilterPolicy) { p.PII.MaxCharsPerRequest = 128 },
			wantReason: ReasonPIIMaxCharsTooSmall,
		},
		{
			name:       "rule4_parallelism_out_of_bounds",
			mutate:     func(p *MCPContentFilterPolicy) { p.PII.MaxParallelChunks = 0 },
			wantReason: ReasonParallelismOutOfBounds,
		},
		{
			name:       "rule5_body_cap_out_of_bounds",
			mutate:     func(p *MCPContentFilterPolicy) { p.Wire.MaxBodyBytes = 1 },
			wantReason: ReasonBodyCapOutOfBounds,
		},
		{
			name: "rule6_cache_ttl_too_short",
			mutate: func(p *MCPContentFilterPolicy) {
				p.PII.TimeoutSeconds = 60
				p.Cache.TTLSeconds = 10
			},
			wantReason: ReasonCacheTTLTooShort,
		},
		{
			name: "rule7_breaker_reset_too_short",
			mutate: func(p *MCPContentFilterPolicy) {
				p.PII.TimeoutSeconds = 60
				p.Breaker.ResetSeconds = 30
			},
			wantReason: ReasonBreakerResetTooShort,
		},
		{
			name: "rule9_jira_enabled_but_no_creds",
			mutate: func(p *MCPContentFilterPolicy) {
				p.Backends.EnableJira = true
				// keep Jira.BaseURL/Email/Token empty
			},
			wantReason: ReasonJiraEnabledButNoCreds,
		},
		{
			name:       "rule10_pii_url_invalid",
			mutate:     func(p *MCPContentFilterPolicy) { p.PII.URL = "gopher://nope" },
			wantReason: ReasonPIIURLInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newValidPolicy()
			tc.mutate(&p)
			err := p.Validate()
			require.Error(t, err)
			var pve *PolicyValidationError
			require.ErrorAs(t, err, &pve)
			require.Equal(t, tc.wantReason, pve.Reason)
		})
	}
}

// TestPolicy_JSONRoundTrip asserts the policy JSON-marshals to the wire
// shape the ConfigMap consumes, and unmarshals back losslessly.
func TestPolicy_JSONRoundTrip(t *testing.T) {
	p := DefaultMCPContentFilterPolicy()
	p.Backends.EnableJira = true
	p.Jira.BaseURL = "https://jira.example.com"
	p.Jira.Email = "bot@example.com"
	p.Jira.APITokenFromEnv = "AIGWCF_JIRA_API_TOKEN"

	data, err := json.Marshal(p)
	require.NoError(t, err)

	var got MCPContentFilterPolicy
	require.NoError(t, json.Unmarshal(data, &got))

	require.Equal(t, p, got)
}
