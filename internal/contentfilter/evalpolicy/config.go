// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"fmt"
	"os"
	"strings"
)

// defaultEndpoint is the hack-reason endpoint used by PR 95. It is
// deliberately reproduced verbatim so an operator can drop this
// service into the PR 95 evaluation setup without config changes.
// Change it via Config.Endpoint in production deployments.
const defaultEndpoint = "https://hkn12.ai.nutanix.com/enterpriseai/v1/chat/completions"

// defaultModel mirrors the PR 95 default. Kept in sync with the Python
// hook so `diff`s between the two implementations stay limited to
// behavioural code.
const defaultModel = "hack-reason"

// defaultAPIKeyEnv mirrors the PR 95 default env var name. This is a
// variable NAME, not a credential; the #nosec annotation silences the
// gosec false positive that flags any `_KEY` suffix.
//
//nolint:gosec // G101: env var name, not a secret.
const defaultAPIKeyEnv = "LLM_API_KEY"

// defaultTimeoutSeconds mirrors the PR 95 default (60s). The LLM
// endpoint the hack-reason model runs behind has been measured at
// p95 ~8s / p99 ~30s; 60s gives room for tail latency without
// queueing requests inside the service.
const defaultTimeoutSeconds = 60

// defaultTicketHeader is the HTTP header the policy consults for a
// per-call override of [Config.EvalTicketID]. PR 95 used the env var
// alone because each cursor-cli run was a single ticket; the gateway
// serves multiple concurrent evaluations so the header path is the
// more useful default.
const defaultTicketHeader = "X-Eval-Ticket-Id"

// Config is the runtime configuration for the eval policy. All fields
// are loaded from the content-filter service's ServerConfig, which is
// in turn loaded from a JSON file on disk (typically a ConfigMap
// mount). ApplyDefaults fills in zero-valued fields with the PR 95
// defaults; Validate enforces the few invariants that matter at
// startup (rather than first-request time).
type Config struct {
	// Endpoint is the OpenAI-compatible chat/completions URL the
	// policy POSTs to. The default points at the internal
	// hack-reason endpoint used during PR 95 development; override
	// for any other deployment.
	Endpoint string `json:"endpoint,omitempty"`

	// Model is the model name sent in the request payload.
	// Defaults to "hack-reason" to match PR 95. The model MUST be
	// fast (<10s p95) because the policy runs in line with each
	// filtered tool call.
	Model string `json:"model,omitempty"`

	// APIKeyEnv is the name of the environment variable that
	// carries the bearer token for the LLM call. Mirrors PR 95's
	// `llm.api_key_env`. Defaults to "LLM_API_KEY". The policy
	// reads the env var fresh on each call so credential rotation
	// does not require a restart.
	APIKeyEnv string `json:"apiKeyEnv,omitempty"`

	// APIKeyFile is an optional path to a file whose contents are
	// used as the bearer token when APIKeyEnv is unset or empty.
	// Typically a Kubernetes Secret mounted into the pod. The file
	// is read on each call (cheap, O(32B)) so token rotation does
	// not require a restart here either.
	APIKeyFile string `json:"apiKeyFile,omitempty"`

	// TimeoutSeconds caps the per-call wall time of the LLM
	// request. Defaults to 60s (PR 95 value). MUST be positive if
	// set; 0 uses the default.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	// Temperature is the model sampling temperature. Defaults to
	// 0 for deterministic redaction — tests and evaluations rely
	// on stable outputs for the same input. Overriding above 0
	// makes the redactor non-deterministic; do so only for
	// research experiments.
	Temperature float64 `json:"temperature,omitempty"`

	// InsecureSkipTLSVerify disables TLS certificate verification
	// on the outbound LLM call. PR 95 set this unconditionally
	// because the internal Nutanix endpoint uses a cert that is
	// not in the default CA bundle. Expose it as a config knob so
	// the same service can also talk to public endpoints with
	// proper verification. Defaults to false.
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// FilteredTools is the allowlist of MCP tool names this
	// policy should actually invoke the LLM on. Requests for
	// tools outside this list short-circuit to
	// [wire.ActionPass]. Matches PR 95's `filtered_tools` list
	// shape; names use the gateway's naming convention (not
	// prefixed with "MCP:" as in the Python hook, because the
	// gateway already scopes by route/backend).
	//
	// An empty list means "no tools are filtered"; this makes the
	// policy a passthrough, useful for smoke-testing the
	// deployment before turning on filtering per tool.
	FilteredTools []string `json:"filteredTools,omitempty"`

	// EvalTicketID is the JIRA/linear ticket id of the evaluation
	// run. Injected into the LLM prompt so self-references in the
	// tool output can be identified and removed. Mirrors
	// EVAL_EXCLUDE_TICKET_ID in PR 95.
	//
	// When a forwarded header named [TicketHeader] is present on
	// the filter request, that value takes precedence — one
	// service pod can then serve many concurrent evaluations
	// without per-run restart.
	EvalTicketID string `json:"evalTicketID,omitempty"`

	// TicketHeader is the forwarded HTTP header name used to
	// override EvalTicketID per call. Defaults to
	// "X-Eval-Ticket-Id". Case-insensitive matching.
	TicketHeader string `json:"ticketHeader,omitempty"`
}

// ApplyDefaults fills unset fields with package defaults. Safe to call
// multiple times; idempotent. Separate from Validate so tests can
// exercise validation against half-set configs.
func (c *Config) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint
	}
	if c.Model == "" {
		c.Model = defaultModel
	}
	if c.APIKeyEnv == "" {
		c.APIKeyEnv = defaultAPIKeyEnv
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaultTimeoutSeconds
	}
	if c.TicketHeader == "" {
		c.TicketHeader = defaultTicketHeader
	}
}

// Validate checks semantic correctness after ApplyDefaults. Returns
// descriptive errors so operators can fix their ConfigMap without
// re-deploying to discover what went wrong.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("eval config is nil")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("eval.endpoint is required")
	}
	if !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("eval.endpoint must be http(s):// URL, got %q", c.Endpoint)
	}
	if c.Model == "" {
		return fmt.Errorf("eval.model is required")
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("eval.timeoutSeconds must be > 0")
	}
	if c.Temperature < 0 {
		return fmt.Errorf("eval.temperature must be >= 0")
	}
	// We do NOT require an API key here — credentials are
	// validated on first use so missing secrets surface as LLM
	// failures (which flow through the safe-redaction fallback)
	// rather than as startup crashes.
	return nil
}

// resolveAPIKey returns the current bearer token. It consults the env
// var first (matching PR 95's precedence), then the file path. An
// empty return value causes the pipeline to enter the safe-redaction
// fallback — the caller does not need to treat missing credentials
// specially.
func (c *Config) resolveAPIKey() string {
	if c == nil {
		return ""
	}
	if c.APIKeyEnv != "" {
		if v := strings.TrimSpace(os.Getenv(c.APIKeyEnv)); v != "" {
			return v
		}
	}
	if c.APIKeyFile != "" {
		raw, err := os.ReadFile(c.APIKeyFile)
		if err == nil {
			return strings.TrimSpace(string(raw))
		}
	}
	return ""
}

// toolFilterSet materialises FilteredTools as a set for O(1) lookup
// per request. Called once from policy construction; re-called only
// in tests that rebuild Config in-place.
func (c *Config) toolFilterSet() map[string]struct{} {
	if c == nil || len(c.FilteredTools) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(c.FilteredTools))
	for _, t := range c.FilteredTools {
		if t != "" {
			out[t] = struct{}{}
		}
	}
	return out
}
