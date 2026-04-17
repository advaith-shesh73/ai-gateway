// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PolicyValidationError is returned by Validate when a cross-field rule fails.
// It carries a stable Reason string that is the same reason the reconciler
// will set on the MCPContentFilter status condition (HANDOFF §6.5).
type PolicyValidationError struct {
	// Reason is a short stable identifier suitable for metrics and status
	// conditions. See the rule table in HANDOFF §6.5.
	Reason string
	// Message is a human-readable description of the violation.
	Message string
	// Field is the dotted JSON path of the offending field, e.g.
	// "pii.maxCharsPerRequest". May be empty when the rule involves
	// multiple fields.
	Field string
}

// Error implements the error interface.
func (e *PolicyValidationError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Reason, e.Message)
	}
	return fmt.Sprintf("%s: %s (field=%s)", e.Reason, e.Message, e.Field)
}

// Reasons returned by Validate. These are stable identifiers that show up
// on status.conditions[].reason and in logs; never rename without a
// controller-side migration.
const (
	ReasonPolicyMismatch            = "PolicyMismatch"
	ReasonTimeoutExceedsUpstream    = "TimeoutExceedsUpstream"
	ReasonPIIMaxCharsTooSmall       = "PIIMaxCharsTooSmall"
	ReasonParallelismOutOfBounds    = "ParallelismOutOfBounds"
	ReasonBodyCapOutOfBounds        = "BodyCapOutOfBounds"
	ReasonCacheTTLTooShort          = "CacheTTLTooShort"
	ReasonBreakerResetTooShort      = "BreakerResetTooShort"
	ReasonStrictEvalConsumerUnknown = "StrictEvalConsumerUnknown" // warn-only
	ReasonJiraEnabledButNoCreds     = "JiraEnabledButNoCreds"
	ReasonPIIURLInvalid             = "PIIURLInvalid"
	ReasonTimeoutInvalid            = "TimeoutInvalid"
	ReasonEvalStrictWithoutHeader   = "EvalStrictWithoutHeader"
	ReasonNoBackendsEnabled         = "NoBackendsEnabled"
)

// Validate runs the full cross-field rule set described in HANDOFF §6.5.
// It returns the FIRST violation encountered so operators can fix one issue
// at a time. For an exhaustive audit (used by the reconciler's admission
// path), callers may call ValidateAll.
//
// Rule ordering is deterministic: rules listed earlier in the HANDOFF table
// are checked earlier so that tests can pin exact reason strings.
//
// Preconditions: Validate assumes ApplyDefaults has been called. Validating
// a zero-value policy without defaults will fail on the first numeric lower
// bound.
func (p *MCPContentFilterPolicy) Validate() error {
	errs := p.ValidateAll()
	if len(errs) == 0 {
		return nil
	}
	return errs[0]
}

// ValidateAll runs every cross-field rule and returns every violation found.
// Used by the reconciler when emitting admission-failure events so that one
// operator edit can surface all the failing rules at once.
//
// The returned slice is never nil and is empty on success.
func (p *MCPContentFilterPolicy) ValidateAll() []*PolicyValidationError {
	if p == nil {
		return []*PolicyValidationError{{
			Reason:  ReasonPolicyMismatch,
			Message: "nil MCPContentFilterPolicy cannot be validated",
		}}
	}

	var errs []*PolicyValidationError
	checks := []func(*MCPContentFilterPolicy) *PolicyValidationError{
		validateRequirePIIFailClosed,
		validatePIIURL,
		validatePIITimeout,
		validatePIIMaxChars,
		validatePIIParallelism,
		validateJiraTimeout,
		validateJiraCreds,
		validateCacheTTL,
		validateBreakerReset,
		validateWireLimits,
		validateEvalHeader,
		validateBackendsEnabled,
	}
	for _, check := range checks {
		if err := check(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// validateRequirePIIFailClosed enforces the core controller-level binding
// (HANDOFF §4.4 P0 #5): when an operator flags RequirePIIFailClosed, the
// PII policy MUST be fail-closed. This is the "single I am in eval mode
// signal" rule: env-var layer is gone, so the reconciler is the sole
// enforcement point.
func validateRequirePIIFailClosed(p *MCPContentFilterPolicy) *PolicyValidationError {
	if p.RequirePIIFailClosed && !p.PII.FailClosed {
		return &PolicyValidationError{
			Reason:  ReasonPolicyMismatch,
			Message: "requirePIIFailClosed=true requires pii.failClosed=true",
			Field:   "pii.failClosed",
		}
	}
	return nil
}

// validatePIIURL checks the URL scheme is http/https and the host is
// non-empty. https is permitted without a rootCAFile — operators are expected
// to trust system CAs, documented in README.
func validatePIIURL(p *MCPContentFilterPolicy) *PolicyValidationError {
	if p.PII.URL == "" {
		return &PolicyValidationError{
			Reason:  ReasonPIIURLInvalid,
			Message: "pii.url is required",
			Field:   "pii.url",
		}
	}
	u, err := url.Parse(p.PII.URL)
	if err != nil {
		return &PolicyValidationError{
			Reason:  ReasonPIIURLInvalid,
			Message: fmt.Sprintf("pii.url is not a valid URL: %v", err),
			Field:   "pii.url",
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &PolicyValidationError{
			Reason:  ReasonPIIURLInvalid,
			Message: fmt.Sprintf("pii.url scheme %q is not allowed (want http or https)", u.Scheme),
			Field:   "pii.url",
		}
	}
	if u.Host == "" {
		return &PolicyValidationError{
			Reason:  ReasonPIIURLInvalid,
			Message: "pii.url must include a host",
			Field:   "pii.url",
		}
	}
	return nil
}

// validatePIITimeout ensures TimeoutSeconds > 0. Python refuses to start
// with <= 0 (AppConfig.validate()).
func validatePIITimeout(p *MCPContentFilterPolicy) *PolicyValidationError {
	if p.PII.TimeoutSeconds <= 0 {
		return &PolicyValidationError{
			Reason:  ReasonTimeoutInvalid,
			Message: fmt.Sprintf("pii.timeoutSeconds must be > 0 (got %v)", p.PII.TimeoutSeconds),
			Field:   "pii.timeoutSeconds",
		}
	}
	return nil
}

// validatePIIMaxChars enforces Rule #3: MaxCharsPerRequest >= 1024.
// Python's minimum is 1 but the port hardens it to 1024 so that a
// misconfigured ConfigMap can't degrade PII throughput to one call per byte.
func validatePIIMaxChars(p *MCPContentFilterPolicy) *PolicyValidationError {
	const minChars = 1024
	if p.PII.MaxCharsPerRequest < minChars {
		return &PolicyValidationError{
			Reason: ReasonPIIMaxCharsTooSmall,
			Message: fmt.Sprintf(
				"pii.maxCharsPerRequest=%d is below minimum %d",
				p.PII.MaxCharsPerRequest, minChars,
			),
			Field: "pii.maxCharsPerRequest",
		}
	}
	return nil
}

// validatePIIParallelism enforces Rule #4: both parallelism knobs are in
// [1, 32]. Upper bound prevents accidental fan-out explosion; lower bound
// matches Python's AppConfig.validate().
func validatePIIParallelism(p *MCPContentFilterPolicy) *PolicyValidationError {
	const (
		minPar = 1
		maxPar = 32
	)
	if p.PII.MaxParallelParts < minPar || p.PII.MaxParallelParts > maxPar {
		return &PolicyValidationError{
			Reason: ReasonParallelismOutOfBounds,
			Message: fmt.Sprintf(
				"pii.maxParallelParts=%d is outside [%d, %d]",
				p.PII.MaxParallelParts, minPar, maxPar,
			),
			Field: "pii.maxParallelParts",
		}
	}
	if p.PII.MaxParallelChunks < minPar || p.PII.MaxParallelChunks > maxPar {
		return &PolicyValidationError{
			Reason: ReasonParallelismOutOfBounds,
			Message: fmt.Sprintf(
				"pii.maxParallelChunks=%d is outside [%d, %d]",
				p.PII.MaxParallelChunks, minPar, maxPar,
			),
			Field: "pii.maxParallelChunks",
		}
	}
	return nil
}

// validateJiraTimeout ensures Jira.TimeoutSeconds > 0 when the Jira handler
// is enabled. Unlike PII, a Jira timeout of 0 is allowed when the handler
// is disabled — the field defaults to 15 anyway via ApplyDefaults but an
// operator might explicitly zero it while EnableJira=false.
func validateJiraTimeout(p *MCPContentFilterPolicy) *PolicyValidationError {
	if !p.Backends.EnableJira {
		return nil
	}
	if p.Jira.TimeoutSeconds <= 0 {
		return &PolicyValidationError{
			Reason:  ReasonTimeoutInvalid,
			Message: fmt.Sprintf("jira.timeoutSeconds must be > 0 when jira handler enabled (got %v)", p.Jira.TimeoutSeconds),
			Field:   "jira.timeoutSeconds",
		}
	}
	return nil
}

// validateJiraCreds enforces Rule #9: enabling the Jira handler requires
// BaseURL + at least one of APITokenFromEnv or APITokenFile.
func validateJiraCreds(p *MCPContentFilterPolicy) *PolicyValidationError {
	if !p.Backends.EnableJira {
		return nil
	}
	if p.Jira.BaseURL == "" {
		return &PolicyValidationError{
			Reason:  ReasonJiraEnabledButNoCreds,
			Message: "backends.enableJira=true requires jira.baseURL",
			Field:   "jira.baseURL",
		}
	}
	if p.Jira.APITokenFromEnv == "" && p.Jira.APITokenFile == "" {
		return &PolicyValidationError{
			Reason:  ReasonJiraEnabledButNoCreds,
			Message: "backends.enableJira=true requires one of jira.apiTokenFromEnv or jira.apiTokenFile",
			Field:   "jira.apiTokenFromEnv",
		}
	}
	if p.Jira.Email == "" {
		return &PolicyValidationError{
			Reason:  ReasonJiraEnabledButNoCreds,
			Message: "backends.enableJira=true requires jira.email for Basic auth",
			Field:   "jira.email",
		}
	}
	return nil
}

// validateCacheTTL enforces Rule #6: cache TTL must outlive an in-flight
// call, i.e. Cache.TTLSeconds >= PII.TimeoutSeconds. A shorter TTL means a
// cached entry could expire while a caller still holds a reference, causing
// a re-fetch against a still-inflight downstream call.
func validateCacheTTL(p *MCPContentFilterPolicy) *PolicyValidationError {
	if !p.Cache.Enabled {
		return nil
	}
	if p.Cache.TTLSeconds < p.PII.TimeoutSeconds {
		return &PolicyValidationError{
			Reason: ReasonCacheTTLTooShort,
			Message: fmt.Sprintf(
				"cache.ttlSeconds=%v must be >= pii.timeoutSeconds=%v",
				p.Cache.TTLSeconds, p.PII.TimeoutSeconds,
			),
			Field: "cache.ttlSeconds",
		}
	}
	return nil
}

// validateBreakerReset enforces Rule #7: breaker reset must be >= 2x PII
// timeout, so that a slow call doesn't get caught in the breaker's
// reset-and-retry cycle mid-flight.
func validateBreakerReset(p *MCPContentFilterPolicy) *PolicyValidationError {
	if !p.Breaker.Enabled {
		return nil
	}
	minReset := 2 * p.PII.TimeoutSeconds
	if p.Breaker.ResetSeconds < minReset {
		return &PolicyValidationError{
			Reason: ReasonBreakerResetTooShort,
			Message: fmt.Sprintf(
				"breaker.resetSeconds=%v must be >= 2 * pii.timeoutSeconds=%v",
				p.Breaker.ResetSeconds, minReset,
			),
			Field: "breaker.resetSeconds",
		}
	}
	return nil
}

// validateWireLimits enforces Rule #5: Wire.MaxBodyBytes ∈ [64 KiB, 64 MiB].
func validateWireLimits(p *MCPContentFilterPolicy) *PolicyValidationError {
	const (
		minBytes int64 = 64 << 10 // 64 KiB
		maxBytes int64 = 64 << 20 // 64 MiB
	)
	if p.Wire.MaxBodyBytes < minBytes || p.Wire.MaxBodyBytes > maxBytes {
		return &PolicyValidationError{
			Reason: ReasonBodyCapOutOfBounds,
			Message: fmt.Sprintf(
				"wire.maxBodyBytes=%d is outside [%d, %d]",
				p.Wire.MaxBodyBytes, minBytes, maxBytes,
			),
			Field: "wire.maxBodyBytes",
		}
	}
	return nil
}

// validateEvalHeader enforces that strict=true cannot be combined with an
// empty header name. Without a header name there's nothing to validate
// strictly against, so the combination is pure misconfiguration.
func validateEvalHeader(p *MCPContentFilterPolicy) *PolicyValidationError {
	if p.Eval.Strict && strings.TrimSpace(p.Eval.Name) == "" {
		return &PolicyValidationError{
			Reason:  ReasonEvalStrictWithoutHeader,
			Message: "evalHeader.strict=true requires a non-empty evalHeader.name",
			Field:   "evalHeader.name",
		}
	}
	return nil
}

// validateBackendsEnabled enforces that AT LEAST ONE backend handler is
// enabled. A policy with every handler off would pass every request
// unchanged, defeating the filter.
func validateBackendsEnabled(p *MCPContentFilterPolicy) *PolicyValidationError {
	b := p.Backends
	if !b.EnableSupportGPT && !b.EnableNuRAG && !b.EnableGlean && !b.EnableJira && !b.EnableDefaultPII {
		return &PolicyValidationError{
			Reason:  ReasonNoBackendsEnabled,
			Message: "at least one backend handler must be enabled (supportgpt/nurag/glean/jira/default)",
			Field:   "backends",
		}
	}
	return nil
}

// IsPolicyValidationError reports whether err wraps a PolicyValidationError.
// Used by the reconciler to decide whether to surface the Reason on status
// conditions versus treating the error as an internal failure.
func IsPolicyValidationError(err error) bool {
	var pve *PolicyValidationError
	return errors.As(err, &pve)
}
