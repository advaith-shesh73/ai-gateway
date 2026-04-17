// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

// MCPContentFilterPolicy holds the cluster-scoped tunables for the in-process
// MCP content filter. It is loaded once at startup from a ConfigMap referenced
// by --content-filter-policy-configmap=<namespace>/<name>, or embedded in the
// compiled MCPContentFilter envelope when a route opts into in-process
// filtering.
//
// Parity: this is the Go port of the AIGWCF_* env var surface that lives in
// services/aigw-content-filter/app/config.py (~lines 69-262). The mapping
// table is documented in docs/handoffs/HANDOFF_GO_PORT_REFERENCE.md §6.3.
//
// Design notes:
//   - Every field has a safe default applied by ApplyDefaults(). Callers must
//     invoke ApplyDefaults before Validate so that a partially populated policy
//     (e.g. from a minimal ConfigMap) is fully specified before the cross-field
//     rules fire.
//   - Validation is split into two phases so that tests can exercise the rules
//     independently of default application.
//   - The struct is copy-safe (all fields are value types or simple slices/maps)
//     so that a snapshot can be stored on the compiled contentFilter without
//     accidental sharing between routes.
type MCPContentFilterPolicy struct {
	// PII groups all knobs controlling the PII anonymization client.
	PII PIIPolicy `json:"pii"`
	// Cache groups the LRU + TTL tunables fronting the PII client.
	Cache CachePolicy `json:"cache"`
	// Breaker groups the circuit-breaker tunables for PII (and a distinct
	// breaker is constructed from JiraPolicy for the Jira client).
	Breaker BreakerPolicy `json:"breaker"`
	// Jira groups credentials and HTTP-pool knobs for the Atlassian Jira
	// T0-reconstruction client.
	Jira JiraPolicy `json:"jira"`
	// Backends controls per-backend handler toggles and the PII-scan
	// fallback allowlist used by the DefaultHandler.
	Backends BackendPolicy `json:"backends"`
	// Eval configures the x-eval-exclude-ticket-id header name and strict
	// ambiguity behavior.
	Eval EvalHeaderPolicy `json:"evalHeader"`
	// Wire caps request/response body size BEFORE dispatcher parsing. This
	// is the Go-side port of AIGWCF_WIRE_MAX_BODY_BYTES. Kept even though
	// the HTTP "wire" no longer exists; the cap still protects the
	// dispatcher from pathological payloads.
	Wire WireLimits `json:"wire"`
	// RequirePIIFailClosed is the Go port of AIGWCF_REQUIRE_PII_FAIL_CLOSED.
	// When true, Validate() will refuse any policy whose PII.FailClosed is
	// false; the gateway must crash rather than silently ship fail-open.
	RequirePIIFailClosed bool `json:"requirePIIFailClosed"`

	// GlobalDisable is the process-wide kill switch. When true, every
	// MCPContentFilter attached to any backend is short-circuited:
	// the gateway emits X-Content-Filter-Status: disabled, records
	// mcp_filter_status_total with status=disabled, and forwards the
	// original body unchanged. Intended for incident response where
	// operators need one lever to disable filtering for the whole
	// cluster without editing every MCPGatewayRoute. The ConfigMap
	// this ships in is typically reloaded hot (no gateway restart).
	//
	// Defaults to false so a missing or empty ConfigMap leaves
	// filtering fully active.
	GlobalDisable bool `json:"globalDisable,omitempty"`
}

// PIIPolicy mirrors the Python AppConfig.pii_* fields and the new Go-only
// HTTP-pool knobs.
type PIIPolicy struct {
	// URL is the /anonymize endpoint of the GPU PII service.
	URL string `json:"url"`
	// TimeoutSeconds is the per-call deadline. Applied to the Go
	// http.Client via context.WithTimeout, NOT http.Client.Timeout, so
	// that the ambient request context's cancellation semantics win.
	TimeoutSeconds float64 `json:"timeoutSeconds"`
	// FailClosed flips chunk failures between fail-open (return original
	// text) and fail-closed (raise PIIServiceError so the handler rejects
	// the whole call with JSON-RPC code -32010).
	FailClosed bool `json:"failClosed"`
	// MaxCharsPerRequest is the maximum rune length of a single chunk
	// sent to the anonymize endpoint. Longer inputs are split by
	// splitForPII and fanned out across up to MaxParallelChunks goroutines.
	MaxCharsPerRequest int `json:"maxCharsPerRequest"`
	// MaxParallelChunks bounds concurrent chunks within ONE anonymize()
	// call. Guards the GPU's per-request queue.
	MaxParallelChunks int `json:"maxParallelChunks"`
	// MaxParallelParts bounds concurrent text parts across ONE response
	// handler invocation. Separate from MaxParallelChunks so a response
	// with 50 text parts does not explode into 50 * MaxParallelChunks
	// in-flight calls.
	MaxParallelParts int `json:"maxParallelParts"`
	// HTTPMaxConnections caps total concurrent connections per host on
	// the PII client's Transport (ports http.Transport.MaxConnsPerHost).
	HTTPMaxConnections int `json:"httpMaxConnections"`
	// HTTPMaxIdle caps idle connections per host (ports
	// http.Transport.MaxIdleConnsPerHost).
	HTTPMaxIdle int `json:"httpMaxIdle"`
}

// CachePolicy tunes the LRU + TTL cache that fronts the PII client.
type CachePolicy struct {
	// Enabled toggles the cache. When false the PII client constructs no
	// cache and every anonymize() call goes out to the network.
	Enabled bool `json:"enabled"`
	// MaxEntries caps the number of (context,text) pairs the cache holds.
	MaxEntries int `json:"maxEntries"`
	// TTLSeconds is the per-entry expiration window.
	TTLSeconds float64 `json:"ttlSeconds"`
}

// BreakerPolicy tunes the circuit breaker protecting the PII client.
type BreakerPolicy struct {
	// Enabled toggles the breaker. When false the PII client attempts
	// every call regardless of recent failures.
	Enabled bool `json:"enabled"`
	// FailureThreshold is the consecutive-failure count that transitions
	// the breaker from CLOSED to OPEN.
	FailureThreshold int `json:"failureThreshold"`
	// ResetSeconds is how long OPEN lasts before probing HALF_OPEN.
	ResetSeconds float64 `json:"resetSeconds"`
}

// JiraPolicy configures the Atlassian Jira Cloud client used for T0 ticket
// reconstruction. A distinct HTTP client + breaker is used so a slow Jira
// poll cannot consume a PII pool slot and vice versa (HANDOFF §4.10).
type JiraPolicy struct {
	// BaseURL is the Jira Cloud instance URL (e.g. https://jira.example.com).
	BaseURL string `json:"baseURL"`
	// Email is the account email used for Basic auth.
	Email string `json:"email"`
	// APITokenFromEnv is the name of an env var containing the Atlassian
	// API token. Used in preference to APITokenFile when both are set.
	APITokenFromEnv string `json:"apiTokenFromEnv"`
	// APITokenFile is the path to a file containing the API token. Used
	// when APITokenFromEnv is unset. Falls back to the empty token when
	// neither is available (disables the Jira handler).
	APITokenFile string `json:"apiTokenFile"`
	// TimeoutSeconds is the per-call deadline for Jira REST operations.
	TimeoutSeconds float64 `json:"timeoutSeconds"`
	// HTTPMaxConnections caps total concurrent connections per host on
	// the Jira client's Transport.
	HTTPMaxConnections int `json:"httpMaxConnections"`
	// HTTPMaxIdle caps idle connections per host on the Jira client.
	HTTPMaxIdle int `json:"httpMaxIdle"`
	// BreakerFailureThreshold is the consecutive-failure count that
	// transitions the Jira breaker from CLOSED to OPEN.
	BreakerFailureThreshold int `json:"breakerFailureThreshold"`
	// BreakerResetSeconds is how long OPEN lasts before probing HALF_OPEN
	// on the Jira breaker.
	BreakerResetSeconds float64 `json:"breakerResetSeconds"`
}

// BackendPolicy toggles per-backend handlers and configures the default
// PII-scan fallback allowlist.
type BackendPolicy struct {
	// Handlers is an optional override map: backend name → handler kind.
	// Omitted entries default to the built-in per-backend handler.
	// Currently used only by dispatcher tests to inject a synthetic
	// handler; production loads implicitly from the per-backend toggles.
	Handlers map[string]string `json:"handlers,omitempty"`
	// PIIScanBackends lists which backend names get PII-scan fallback
	// when no specific handler matches (DefaultHandler behavior).
	PIIScanBackends []string `json:"piiScanBackends,omitempty"`
	// EnableSupportGPT toggles the SupportGPT handler (exclude_ticket_ids).
	EnableSupportGPT bool `json:"enableSupportGPT"`
	// EnableNuRAG toggles the NuRAG handler (exclude_sources).
	EnableNuRAG bool `json:"enableNuRAG"`
	// EnableGlean toggles the Glean handler (query -ticket:<id>).
	EnableGlean bool `json:"enableGlean"`
	// EnableJira toggles the Jira handler (T0 reconstruction + JQL rewrite).
	EnableJira bool `json:"enableJira"`
	// EnableDefaultPII toggles the DefaultHandler PII-scan fallback.
	EnableDefaultPII bool `json:"enableDefaultPII"`
	// SupportGPTBackendNames maps which backend names route to the
	// SupportGPT handler. Defaults to {"supportgpt"} via ApplyDefaults.
	SupportGPTBackendNames []string `json:"supportGPTBackendNames,omitempty"`
	// NuRAGBackendNames maps which backend names route to the NuRAG
	// handler. Defaults to {"nurag"} via ApplyDefaults.
	NuRAGBackendNames []string `json:"nurAGBackendNames,omitempty"`
	// GleanBackendNames maps which backend names route to the Glean
	// handler. Defaults to {"glean"} via ApplyDefaults.
	GleanBackendNames []string `json:"gleanBackendNames,omitempty"`
	// JiraBackendNames maps which backend names route to the Jira
	// handler. Defaults to {"atlassian","jira"} via ApplyDefaults.
	JiraBackendNames []string `json:"jiraBackendNames,omitempty"`
}

// EvalHeaderPolicy configures the eval-mode header.
type EvalHeaderPolicy struct {
	// Name is the header name carrying the target ticket ID.
	// Lowercased canonical form; e.g. "x-eval-exclude-ticket-id".
	Name string `json:"name"`
	// Strict controls behavior on multi-valued headers: when true, the
	// dispatcher rejects with JSON-RPC -32600; when false, it takes the
	// first non-"none" token and increments
	// filter_eval_header_ambiguous_total.
	Strict bool `json:"strict"`
}

// WireLimits caps request/response body size BEFORE dispatcher parsing.
// Go-only knob (no Python counterpart beyond the env var).
type WireLimits struct {
	// MaxBodyBytes is the hard upper bound for a single dispatch body.
	MaxBodyBytes int64 `json:"maxBodyBytes"`
}

// --- Defaults ------------------------------------------------------------

// defaultPIIServiceURL is the in-cluster PII service DNS name. Matches the
// Python default (app/config.py line 59).
const defaultPIIServiceURL = "http://pii-service.pii.svc.cluster.local:8081/anonymize"

// Default PII-scan backend allowlist — mirrors app/config.py:pii_scan_backends.
var defaultPIIScanBackends = []string{
	"nurag", "supportgpt", "atlassian", "jira", "glean", "panacea",
}

// ApplyDefaults fills in any zero-valued knob with its documented default.
// Callers invoking Validate on a partially populated policy MUST call
// ApplyDefaults first; the cross-field rules assume post-default values.
//
// ApplyDefaults is idempotent: calling it twice produces identical output.
// It never modifies an explicitly set value even if that value is the same
// as the default (so operator intent is preserved on round-trip serialization).
func (p *MCPContentFilterPolicy) ApplyDefaults() {
	if p == nil {
		return
	}

	if p.PII.URL == "" {
		p.PII.URL = defaultPIIServiceURL
	}
	if p.PII.TimeoutSeconds == 0 {
		p.PII.TimeoutSeconds = 60
	}
	if p.PII.MaxCharsPerRequest == 0 {
		p.PII.MaxCharsPerRequest = 40000
	}
	if p.PII.MaxParallelChunks == 0 {
		p.PII.MaxParallelChunks = 4
	}
	if p.PII.MaxParallelParts == 0 {
		p.PII.MaxParallelParts = 4
	}
	if p.PII.HTTPMaxConnections == 0 {
		p.PII.HTTPMaxConnections = 100
	}
	if p.PII.HTTPMaxIdle == 0 {
		p.PII.HTTPMaxIdle = 20
	}

	if p.Cache.MaxEntries == 0 {
		p.Cache.MaxEntries = 2048
	}
	if p.Cache.TTLSeconds == 0 {
		p.Cache.TTLSeconds = 900
	}

	if p.Breaker.FailureThreshold == 0 {
		p.Breaker.FailureThreshold = 10
	}
	if p.Breaker.ResetSeconds == 0 {
		// The cross-field rule in Validate() requires the breaker reset
		// window to be >= 2 * PII.TimeoutSeconds so an in-flight call
		// cannot be interrupted mid-reset. With the default PII timeout
		// of 60s this yields 120s. Operators who want a shorter reset
		// must also shrink PII.TimeoutSeconds; the validator enforces
		// the ratio at load time.
		minReset := 2 * p.PII.TimeoutSeconds
		if minReset < 30 {
			minReset = 30
		}
		p.Breaker.ResetSeconds = minReset
	}

	if p.Jira.TimeoutSeconds == 0 {
		p.Jira.TimeoutSeconds = 15
	}
	if p.Jira.HTTPMaxConnections == 0 {
		p.Jira.HTTPMaxConnections = 20
	}
	if p.Jira.HTTPMaxIdle == 0 {
		p.Jira.HTTPMaxIdle = 10
	}
	if p.Jira.BreakerFailureThreshold == 0 {
		p.Jira.BreakerFailureThreshold = 5
	}
	if p.Jira.BreakerResetSeconds == 0 {
		p.Jira.BreakerResetSeconds = 30
	}

	if len(p.Backends.PIIScanBackends) == 0 {
		p.Backends.PIIScanBackends = append([]string(nil), defaultPIIScanBackends...)
	}
	if len(p.Backends.SupportGPTBackendNames) == 0 {
		p.Backends.SupportGPTBackendNames = []string{"supportgpt"}
	}
	if len(p.Backends.NuRAGBackendNames) == 0 {
		p.Backends.NuRAGBackendNames = []string{"nurag"}
	}
	if len(p.Backends.GleanBackendNames) == 0 {
		p.Backends.GleanBackendNames = []string{"glean"}
	}
	if len(p.Backends.JiraBackendNames) == 0 {
		p.Backends.JiraBackendNames = []string{"atlassian", "jira"}
	}

	if p.Eval.Name == "" {
		p.Eval.Name = "x-eval-exclude-ticket-id"
	}

	if p.Wire.MaxBodyBytes == 0 {
		p.Wire.MaxBodyBytes = 2 << 20 // 2 MiB, matches contentFilterMaxBodyBytes
	}
}

// DefaultMCPContentFilterPolicy returns a fully-defaulted policy with the
// non-credentialed per-backend handlers enabled. Jira is left disabled
// because enabling it without credentials fails Rule #9; operators must
// explicitly opt in after configuring Jira.BaseURL / Email / credentials.
//
// Callers who want Jira enabled must set EnableJira=true AND populate the
// JiraPolicy fields; Validate() will then accept the result.
func DefaultMCPContentFilterPolicy() MCPContentFilterPolicy {
	p := MCPContentFilterPolicy{
		Backends: BackendPolicy{
			EnableSupportGPT: true,
			EnableNuRAG:      true,
			EnableGlean:      true,
			EnableJira:       false,
			EnableDefaultPII: true,
		},
		Cache:   CachePolicy{Enabled: true},
		Breaker: BreakerPolicy{Enabled: true},
	}
	p.ApplyDefaults()
	return p
}
