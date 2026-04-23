// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

import (
	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// MCPRoute defines how to route MCP requests to the backend MCP servers.
//
// This serves as a way to define a "unified" AI API for a Gateway which allows downstream
// clients to use a single schema API to interact with multiple MCP backends.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[-1:].type`
type MCPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec defines the details of the MCPRoute.
	Spec MCPRouteSpec `json:"spec,omitempty"`
	// Status defines the status details of the MCPRoute.
	Status MCPRouteStatus `json:"status,omitempty"`
}

// MCPRouteList contains a list of MCPRoute.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type MCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPRoute `json:"items"`
}

// MCPRouteSpec details the MCPRoute configuration.
type MCPRouteSpec struct {
	// ParentRefs are the names of the Gateway resources this MCPRoute is being attached to.
	// Cross namespace references are not supported. In other words, the Gateway resources must be in the
	// same namespace as the MCPRoute. Currently, each reference's Kind must be Gateway.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(match, match.kind == 'Gateway')", message="only Gateway is supported"
	ParentRefs []gwapiv1.ParentReference `json:"parentRefs"`

	// Path is the HTTP endpoint path that serves MCP requests over the Streamable HTTP transport.
	// If not specified, the default is "/mcp".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=/mcp
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// Headers are HTTP headers that must match for this route to be selected.
	// Multiple match values are ANDed together, meaning, a request must match all the specified headers to select the route.
	//
	// +listType=map
	// +listMapKey=name
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Headers []gwapiv1.HTTPHeaderMatch `json:"headers,omitempty"`

	// BackendRefs is a list of backend references to the MCP servers.
	// These MCP servers will be aggregated and exposed as a single MCP endpoint to the clients.
	// From the client's perspective, they only need to configure a single MCP server URL, e.g. "https://api.example.com/mcp",
	// and the Envoy AI Gateway will route the requests to the appropriate MCP server based on the requests.
	//
	// All names must be unique within this list to avoid potential tools, resources, etc. name collisions.
	// Also, cross-namespace references are not supported. In other words, the backend MCP servers must be in the
	// same namespace as the MCPRoute.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:XValidation:rule="self.all(i, self.exists_one(j, j.name == i.name))", message="all backendRefs names must be unique"
	BackendRefs []MCPRouteBackendRef `json:"backendRefs"`

	// SecurityPolicy defines the security policy for this MCPRoute.
	//
	// +kubebuilder:validation:Optional
	// +optional
	SecurityPolicy *MCPRouteSecurityPolicy `json:"securityPolicy,omitempty"`
}

// MCPRouteBackendRef wraps a EG's BackendObjectReference to reference an MCP server.
// TODO: move to a standalone MCPBackend CRD to avoid k8s object size limit.
type MCPRouteBackendRef struct {
	gwapiv1.BackendObjectReference `json:",inline"`

	// Path is the HTTP endpoint path of the baackend MCP server.
	// If not specified, the default is "/mcp".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=/mcp
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// ToolSelector filters the tools exposed by this MCP server.
	// Supports exact matches and RE2-compatible regular expressions for both include and exclude patterns.
	// If not specified, all tools from the MCP server are exposed.
	// +kubebuilder:validation:Optional
	// +optional
	ToolSelector *MCPToolFilter `json:"toolSelector,omitempty"`

	// TODO: we can add resource and prompt selectors in the future.

	// SecurityPolicy is the security policy to apply to this MCP server.
	//
	// +kubebuilder:validation:Optional
	// +optional
	SecurityPolicy *MCPBackendSecurityPolicy `json:"securityPolicy,omitempty"`

	// ContentFilter configures an optional external HTTP service that inspects
	// and may rewrite "tools/call" payloads for this backend before they are
	// forwarded to the MCP server (request scope) and/or after the response
	// is returned (response scope).
	//
	// Typical uses are PII scrubbing and evaluation-mode source exclusion,
	// where the gateway needs to rewrite request parameters or response
	// content according to an external policy service.
	//
	// This field is the *inline* form and carries the filter body directly on
	// the backend reference. Operators may alternatively author a standalone
	// top-level MCPContentFilter object whose spec.targetRefs selects this
	// MCPRoute (optionally scoped to this backend by sectionName). When a
	// standalone MCPContentFilter targets this backend, it wins and the inline
	// value here is ignored. See type MCPContentFilter for the standalone form.
	//
	// +kubebuilder:validation:Optional
	// +optional
	ContentFilter *MCPContentFilterConfig `json:"contentFilter,omitempty"`

	// TODO: add fancy per-MCP server config. For example, Rate Limit, etc.
}

// MCPContentFilter is a standalone, top-level policy object that attaches a
// content filter to one or more MCPRoutes (optionally scoped to specific
// backend references) via targetRefs. It is the analogue of
// BackendSecurityPolicy for content filtering: one MCPContentFilter object
// can be authored by a platform/security team and attached to routes owned
// by separate application teams, without requiring edits to the MCPRoute
// spec itself.
//
// # Relationship to the inline form
//
// The inline form lives on [MCPRouteBackendRef.ContentFilter] and carries the
// same filter body ([MCPContentFilterConfig]) directly on the backend
// reference. Operators may use either form, but they are NOT additive: when a
// standalone MCPContentFilter's targetRefs selects a given (MCPRoute,
// backend) pair, the standalone value wins and the inline value on that
// backend reference is ignored. This is consistent with how
// BackendSecurityPolicy overrides inline auth on AIServiceBackend.
//
// The same conflict resolution applies across multiple standalone objects: at
// most one MCPContentFilter may target a given (MCPRoute, backend) pair. A
// second match is a configuration error and the backend's filter collapses to
// nil (plus a controller-emitted log) so traffic fails closed on policy
// ambiguity rather than silently picking a "winner".
//
// # Target granularity
//
// Each entry in spec.targetRefs must have
//
//	group: aigateway.envoyproxy.io
//	kind:  MCPRoute
//	name:  <MCPRoute name>
//
// and may optionally carry
//
//	sectionName: <backend name>
//
// to scope the filter to a single backend reference on the route. Omitting
// sectionName applies the filter to *every* backend on the targeted
// MCPRoute. Cross-namespace references are not supported; the
// MCPContentFilter object must live in the same namespace as the MCPRoute it
// targets.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[-1:].type`
// +kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=direct"
type MCPContentFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the filter configuration and the set of MCPRoute/backend
	// targets this filter attaches to.
	Spec MCPContentFilterSpec `json:"spec,omitempty"`

	// Status defines the status details of the MCPContentFilter.
	Status MCPContentFilterStatus `json:"status,omitempty"`
}

// MCPContentFilterList contains a list of MCPContentFilter.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type MCPContentFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPContentFilter `json:"items"`
}

// MCPContentFilterStatus defines observed state for a standalone
// MCPContentFilter. Conditions follow the Gateway API policy conventions:
//
//   - Accepted:   the controller accepted the spec (references resolve,
//     target type/group is correct, URL is a valid http(s) URI).
//   - Conflicted: another MCPContentFilter already targets one of the
//     same (MCPRoute, backend) pairs; this object's effect is suppressed
//     on the overlapping targets. The message lists the conflicting
//     targets for operator triage.
type MCPContentFilterStatus struct {
	// Conditions is the list of observed conditions for the MCPContentFilter.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// MCPContentFilterSpec defines the desired state of a standalone
// MCPContentFilter. It combines the attachment surface (TargetRefs) with the
// filter body ([MCPContentFilterConfig], inlined).
type MCPContentFilterSpec struct {
	// TargetRefs selects the MCPRoutes (and, optionally via sectionName, the
	// specific backend references on those routes) that this filter attaches
	// to. At least one entry is required for the filter to have any effect.
	//
	// Each entry MUST reference an MCPRoute in the same namespace:
	//
	//	group: aigateway.envoyproxy.io
	//	kind:  MCPRoute
	//	name:  <MCPRoute name>
	//
	// Optionally carry
	//
	//	sectionName: <backend name>
	//
	// to scope the filter to a single backend entry on that MCPRoute. When
	// sectionName is omitted, the filter applies to every backend on the
	// targeted route.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(ref, ref.group == 'aigateway.envoyproxy.io' && ref.kind == 'MCPRoute')", message="targetRefs must reference aigateway.envoyproxy.io/MCPRoute"
	TargetRefs []gwapiv1a2.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`

	// MCPContentFilterConfig is the filter body. It is inlined so a standalone
	// MCPContentFilter spec and an inline MCPRouteBackendRef.contentFilter
	// carry IDENTICAL fields on the wire — only the attachment surface
	// differs.
	MCPContentFilterConfig `json:",inline"`
}

// MCPContentFilterConfig is the shared body of a content filter
// configuration. It is used both inline on [MCPRouteBackendRef.ContentFilter]
// and as the inlined payload of [MCPContentFilterSpec], so operators can move
// a filter between inline and standalone forms without rewriting fields.
//
// For each invocation that matches one of the configured Scopes, the gateway
// POSTs a JSON envelope to URL containing the JSON-RPC message and a subset
// of the client's HTTP headers (selected by ForwardHeaders). The service
// replies with an action of pass, redact, or reject. On redact, the
// replacement JSON-RPC message supplied by the filter is forwarded in place
// of the original. On reject, the gateway returns a JSON-RPC error to the
// client and does not contact the backend (request scope) or forward the
// response (response scope).
type MCPContentFilterConfig struct {
	// URL is the HTTP endpoint of the content filter service. Must use the
	// http:// or https:// scheme. No other schemes are supported.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:Pattern=`^https?://.+$`
	URL string `json:"url"`

	// Scopes selects which phases of the tools/call lifecycle are sent to
	// the filter. At least one must be specified.
	// - "Request":  invoked before the tools/call is forwarded to the backend.
	// - "Response": invoked after the backend returns, before the response is
	//   written to the client.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=2
	// +listType=set
	Scopes []MCPContentFilterScope `json:"scopes"`

	// TimeoutSeconds is the per-invocation timeout applied when calling the
	// filter service. If the filter does not respond before this deadline,
	// FailurePolicy is applied.
	//
	// Defaults to 10 seconds. Must be between 1 and 120 inclusive.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=120
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// FailurePolicy controls behaviour when the gateway cannot obtain a
	// definitive verdict from the filter service. This covers:
	//   - connection refused / TCP reset / TLS handshake failure;
	//   - filter service returns any non-2xx HTTP status;
	//   - response body is not valid JSON or the action field is not one of
	//     pass, redact, reject;
	//   - the filter call exceeds TimeoutSeconds (gateway cancels the
	//     request and treats it as failure).
	//
	// A filter that responds cleanly with action=reject is NOT a failure —
	// it is a deliberate verdict and the gateway always honours it
	// regardless of FailurePolicy (see error code -32010 on the client).
	//
	// - "PassThrough": the original JSON-RPC message is used and the tool
	//   call continues. This is fail-open: the filter outage becomes
	//   invisible to end-users but the gateway does NOT get to inspect the
	//   body. Appropriate for filters whose role is best-effort redaction.
	// - "Fail":        the gateway returns a JSON-RPC error to the client
	//   (code -32011) and does NOT forward the request/response. This is
	//   fail-closed. Appropriate for evaluation and compliance workloads
	//   where an unscanned response is worse than no response.
	//
	// Every failure is observable regardless of policy: the gateway emits
	// X-Content-Filter-Status=failed-open or unavailable, increments
	// mcp_filter_status_total with the corresponding status label, and
	// logs the underlying transport/parse/timeout error. Operators should
	// page on sustained failed-open rates even when configured fail-open.
	//
	// Defaults to "PassThrough".
	//
	// +kubebuilder:validation:Optional
	// +optional
	FailurePolicy *MCPContentFilterFailurePolicy `json:"failurePolicy,omitempty"`

	// ForwardHeaders lists HTTP header names to copy from the client's
	// incoming request into the filter invocation. Header names are
	// case-insensitive. This enables tenant- or context-aware policy (for
	// example, forwarding an evaluation-run ticket ID or a tenant ID).
	//
	// SECURITY: the filter service receives every header named here
	// verbatim. Treat each entry as an intentional trust-boundary
	// decision: the filter host, its logs, and any sidecar/network
	// observer between the gateway and filter can observe the value.
	//   - NEVER list Authorization, Cookie, Set-Cookie, Proxy-Authorization,
	//     or any header carrying a bearer token, session identifier, or
	//     long-lived credential unless the filter is explicitly in-scope
	//     for handling those secrets.
	//   - Prefer opaque identifiers (request ID, tenant ID, evaluation
	//     ticket ID) over headers derived from end-user credentials.
	//   - If the filter runs in a different Kubernetes namespace or trust
	//     zone than the gateway, forwarding user-bearing headers widens
	//     the blast radius of a filter compromise.
	// When in doubt, omit the header.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// +optional
	ForwardHeaders []string `json:"forwardHeaders,omitempty"`

	// Mode selects between Enforce (default) and Shadow. In Shadow mode
	// the gateway still invokes the filter service, records the
	// would-be verdict via X-Content-Filter-Status and
	// mcp_filter_decisions_total, and emits redaction audit events, but
	// always forwards the ORIGINAL body to the client (and backend on
	// Request scope). Use Shadow during pre-production rollout to
	// measure false-positive and false-negative rates on real traffic
	// without impacting users. Operators flip back to Enforce to
	// activate actual enforcement without a gateway restart.
	//
	// Defaults to "Enforce".
	//
	// +kubebuilder:validation:Optional
	// +optional
	Mode *MCPContentFilterMode `json:"mode,omitempty"`

	// Enabled toggles the filter for this backend without removing the
	// configuration. When set to false the gateway forwards the tool
	// call as if no content filter were configured for this backend and
	// reports X-Content-Filter-Status: disabled on the response.
	// Preserving the rest of the configuration lets operators
	// re-enable the filter (possibly with adjusted Mode or
	// FailurePolicy) via a single CRD update, without re-entering
	// URL, scopes, timeout, or headers.
	//
	// Defaults to true. Use the process-wide kill switch
	// (MCPContentFilterPolicyConfig.GlobalDisable, distributed via
	// the policy ConfigMap) to disable every filter in one step
	// during an incident.
	//
	// +kubebuilder:validation:Optional
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// ShadowSampleRatePermille bounds the fraction of invocations
	// actually evaluated when Mode is Shadow. It is expressed in
	// permille (parts per thousand, 0..1000) so operators can set
	// 0.1% granularity on high-traffic backends without switching
	// to floating point. A value of 1000 means every shadow-mode
	// invocation is evaluated (default, preserves backward compat).
	// A value of 0 means the filter is never invoked and every
	// shadow-mode call records action=shadow_sampled_out.
	//
	// Sampling happens BEFORE the filter service is contacted, so
	// values < 1000 provide a hard cost and latency budget: an
	// operator running shadow mode against an expensive LLM-based
	// filter can cap traffic at e.g. 10 permille (1 %) while still
	// producing a statistically meaningful sample for
	// false-positive / false-negative dashboards.
	//
	// Ignored when Mode is Enforce (enforcement always evaluates
	// every call — sampling enforcement would leak content).
	//
	// Defaults to 1000.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	// +optional
	ShadowSampleRatePermille *int32 `json:"shadowSampleRatePermille,omitempty"`

	// Policies names the policy kinds the content-filter service should
	// apply when invoked for this route/backend. The gateway forwards
	// this list verbatim in the filter envelope; it does not interpret
	// the values itself. The filter service acts as a stateless
	// dispatcher, mapping each policy name to its backing engine (for
	// example "pii" -> PII anonymizer, "evalpolicy" -> LLM-backed
	// evaluation-mode anti-leakage), invoking them, and merging the
	// verdicts (reject > redact > pass).
	//
	// This is the single source of truth for "is PII on for this
	// route/backend?". Moving the decision here keeps the filter
	// backend-agnostic and matches the extAuth/AuthorizationPolicy
	// pattern other gateways use: the policy plane owns the what, the
	// filter plane owns the how.
	//
	// An empty or missing list disables all policy execution. The
	// gateway will still invoke the filter at the configured Scopes
	// (useful under Mode=Shadow to measure envelope cost / connectivity
	// without running any engine), but the filter is expected to no-op
	// and return action=pass. Attaching a filter URL without any
	// Policies is explicit opt-in to "the filter is wired but idle";
	// it is NOT the same as leaving the whole ContentFilter unset,
	// which emits X-Content-Filter-Status: off.
	//
	// New policy kinds are added by extending MCPContentFilterPolicy's
	// enum; the gateway does not need to be rebuilt to forward a new
	// name once the enum accepts it.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +optional
	Policies []MCPContentFilterPolicy `json:"policies,omitempty"`
}

// MCPContentFilterPolicy names a policy kind that the content-filter
// service should apply. The gateway forwards this list verbatim in the
// filter envelope; the filter service decides how each name maps to
// its backing engine (PII anonymizer, LLM-backed evalpolicy, future
// policies such as secret scrubbing or prompt-injection detection).
//
// The enum is intentionally small and open-ended. New policies are
// added by extending this type so the CRD schema enforces spelling:
// unknown values are rejected by the Kubernetes API server rather than
// silently forwarded as no-ops. Operators can therefore ship a policy
// name they know the current filter service understands without the
// gateway having to learn its semantics.
//
// +kubebuilder:validation:Enum=pii;evalpolicy
type MCPContentFilterPolicy string

const (
	// MCPContentFilterPolicyPII selects PII / sensitive-data anonymization.
	// The filter service is expected to call its PII engine (for example
	// the pii-service-gpu backing the aigw-content-filter dispatcher) and
	// rewrite the body with placeholders such as [ANONYMIZED_EMAIL] in
	// place of detected PII. Suitable for every backend that returns
	// customer-derived text.
	MCPContentFilterPolicyPII MCPContentFilterPolicy = "pii"

	// MCPContentFilterPolicyEvalPolicy selects the LLM-backed
	// evaluation-mode anti-leakage policy (ticket-ID / transcript
	// redaction). Typically paired with an operator-allowlisted
	// ForwardHeader such as X-Eval-Ticket-Id so the filter can exclude
	// the active evaluation ticket's own content from returned results.
	// Use on backends that surface raw ticket corpora to an evaluator.
	MCPContentFilterPolicyEvalPolicy MCPContentFilterPolicy = "evalpolicy"
)

// MCPContentFilterScope selects a phase of the tools/call lifecycle.
//
// +kubebuilder:validation:Enum=Request;Response
type MCPContentFilterScope string

const (
	// MCPContentFilterScopeRequest invokes the filter before forwarding the
	// tools/call request to the backend.
	MCPContentFilterScopeRequest MCPContentFilterScope = "Request"
	// MCPContentFilterScopeResponse invokes the filter after the backend
	// responds, before the response is written to the client.
	MCPContentFilterScopeResponse MCPContentFilterScope = "Response"
)

// MCPContentFilterFailurePolicy controls how the gateway reacts when the
// filter service is unavailable or errors.
//
// +kubebuilder:validation:Enum=PassThrough;Fail
type MCPContentFilterFailurePolicy string

const (
	// MCPContentFilterFailurePolicyPassThrough forwards the unmodified
	// request or response when the filter service cannot be consulted.
	// This is the default and is fail-open.
	MCPContentFilterFailurePolicyPassThrough MCPContentFilterFailurePolicy = "PassThrough"
	// MCPContentFilterFailurePolicyFail causes the tool call to fail with a
	// JSON-RPC error when the filter service cannot be consulted. Use this
	// when serving unscanned content is worse than failing the call.
	MCPContentFilterFailurePolicyFail MCPContentFilterFailurePolicy = "Fail"
)

// MCPContentFilterMode selects between enforcement and shadow evaluation.
//
// +kubebuilder:validation:Enum=Enforce;Shadow
type MCPContentFilterMode string

const (
	// MCPContentFilterModeEnforce applies the filter's verdict to the
	// client-visible response: on redact the rewritten body is forwarded,
	// on reject a JSON-RPC error is returned. This is the default.
	MCPContentFilterModeEnforce MCPContentFilterMode = "Enforce"
	// MCPContentFilterModeShadow invokes the filter and records the
	// verdict (X-Content-Filter-Status header, mcp_filter_decisions_total
	// counter with action=shadow_would_*, redaction audit events) but
	// forwards the ORIGINAL body to the client. Use Shadow mode for
	// pre-production evaluation: operators can measure what WOULD be
	// redacted or rejected on real traffic before committing to
	// enforcement. Shadow mode never surfaces filter errors as
	// client-visible failures — a would-be reject on a fail-closed
	// policy still forwards the original body, and fail-open
	// behaviour is indistinguishable from a successful would-be pass.
	MCPContentFilterModeShadow MCPContentFilterMode = "Shadow"
)

// MCPToolFilter filters tools using include and exclude patterns with exact matches or regular expressions.
// Exclude rules take precedence over include rules (deny-wins). When both include and exclude are specified,
// a tool must match an include rule AND not match any exclude rule to be allowed.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.include) && has(self.includeRegex))", message="include and includeRegex are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="!(has(self.exclude) && has(self.excludeRegex))", message="exclude and excludeRegex are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="has(self.include) || has(self.includeRegex) || has(self.exclude) || has(self.excludeRegex)", message="at least one of include, includeRegex, exclude, or excludeRegex must be specified"
type MCPToolFilter struct {
	// Include is a list of tool names to include. Only the specified tools will be available.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Include []string `json:"include,omitempty"`

	// IncludeRegex is a list of RE2-compatible regular expressions that, when matched, include the tool.
	// Only tools matching these patterns will be available.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	IncludeRegex []string `json:"includeRegex,omitempty"`

	// Exclude is a list of tool names to exclude. The specified tools will not be available.
	// Exclude rules take precedence over include rules.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Exclude []string `json:"exclude,omitempty"`

	// ExcludeRegex is a list of RE2-compatible regular expressions that, when matched, exclude the tool.
	// Tools matching these patterns will not be available. Exclude rules take precedence over include rules.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ExcludeRegex []string `json:"excludeRegex,omitempty"`
}

// MCPBackendSecurityPolicy defines the security policy for a sp
type MCPBackendSecurityPolicy struct {
	// APIKey is a mechanism to access a backend. The API key will be injected into the request headers.
	// +optional
	APIKey *MCPBackendAPIKey `json:"apiKey,omitempty"`
}

// MCPBackendAPIKey defines the configuration for the API Key Authentication to a backend.
// When both `header` and `queryParam` are unspecified, the API key will be injected into the "Authorization" header by default.
//
// +kubebuilder:validation:XValidation:rule="(has(self.secretRef) && !has(self.inline)) || (!has(self.secretRef) && has(self.inline))", message="exactly one of secretRef or inline must be set"
// +kubebuilder:validation:XValidation:rule="!(has(self.header) && has(self.queryParam))", message="only one of header or queryParam can be set"
type MCPBackendAPIKey struct {
	// secretRef is the Kubernetes secret which contains the API keys.
	// The key of the secret should be "apiKey".
	// +optional
	SecretRef *gwapiv1.SecretObjectReference `json:"secretRef,omitempty"`

	// Inline contains the API key as an inline string.
	//
	// +optional
	Inline *string `json:"inline,omitempty"`

	// Header is the HTTP header to inject the API key into. If not specified,
	// defaults to "Authorization".
	// When the header is "Authorization", the injected header value will be
	// prefixed with "Bearer ".
	//
	// Either one of Header or QueryParam can be specified to inject the API key.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +optional
	Header *string `json:"header,omitempty"`

	// QueryParam is the HTTP query parameter to inject the API key into.
	// For example, if QueryParam is set to "api_key", and the API key is "mysecretkey", the request URL will be modified to include
	// "?api_key=mysecretkey".
	//
	// Either one of Header or QueryParam can be specified to inject the API key.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +optional
	QueryParam *string `json:"queryParam,omitempty"`
}

// MCPRouteSecurityPolicy defines the security policy for a MCPRoute.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.authorization) && self.authorization.rules.exists(r, has(r.source) && has(r.source.jwt)) && !has(self.oauth))",message="oauth must be configured when any authorization rule uses a jwt source"
type MCPRouteSecurityPolicy struct {
	// OAuth defines the configuration for the MCP spec compatible OAuth authentication.
	//
	// +optional
	OAuth *MCPRouteOAuth `json:"oauth,omitempty"`

	// APIKeyAuth defines the configuration for the API Key Authentication.
	//
	// +optional
	APIKeyAuth *egv1a1.APIKeyAuth `json:"apiKeyAuth,omitempty"`

	// ExtAuth defines the configuration for External Authorization.
	//
	// +optional
	ExtAuth *egv1a1.ExtAuth `json:"extAuth,omitempty"`

	// Authorization defines the configuration for the MCP spec compatible authorization.
	//
	// +optional
	Authorization *MCPRouteAuthorization `json:"authorization,omitempty"`
}

// MCPRouteOAuth defines a MCP spec compatible OAuth authentication configuration for a MCPRoute.
// Reference: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
type MCPRouteOAuth struct {
	// Issuer is the authorization server's issuer identity.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=uri
	Issuer string `json:"issuer"`

	// Audiences is a list of JWT audiences allowed access.
	// It is recommended to set this field for token audience validation, as it is a security best practice to prevent token misuse.
	// Reference: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#token-audience-binding-and-validation
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	Audiences []string `json:"audiences"`

	// JWKS defines how a JSON Web Key Sets (JWKS) can be obtained to verify the access tokens presented by the clients.
	//
	// If not specified, the JWKS URI will be discovered from the OAuth 2.0 Authorization Server Metadata
	// as per RFC 8414 by querying the `/.well-known/oauth-authorization-server` endpoint on the Issuer.
	//
	// +optional
	JWKS *JWKS `json:"jwks,omitempty"`

	// ProtectedResourceMetadata defines the OAuth 2.0 Resource Server Metadata as per RFC 8414.
	// This is used to expose the metadata endpoint for mcp clients to discover the authorization servers,
	// supported scopes, and JWKS URI.
	//
	// +kubebuilder:validation:Required
	ProtectedResourceMetadata ProtectedResourceMetadata `json:"protectedResourceMetadata"`

	// ClaimToHeaders specifies JWT claims to extract and forward as HTTP headers to backend MCP servers.
	// This enables backends to access user identity for authorization, auditing, or personalization.
	//
	// Security considerations:
	// - Any client-provided headers matching the configured header names will be stripped to prevent forgery
	// - Only the specified claims are extracted; the full JWT is not forwarded to backends
	// - Consider using a header prefix (e.g., "X-Jwt-Claim-") to avoid conflicts with other headers
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// +optional
	ClaimToHeaders []egv1a1.ClaimToHeader `json:"claimToHeaders,omitempty"`
}

// MCPRouteAuthorization defines the authorization configuration for a MCPRoute.
type MCPRouteAuthorization struct {
	// DefaultAction is the action to take when no rules match. If unspecified, defaults to Deny.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=Deny
	// +optional
	DefaultAction *egv1a1.AuthorizationAction `json:"defaultAction,omitempty"`

	// Rules defines a list of authorization rules.
	// These rules are evaluated in order, the first matching rule will be applied,
	// and the rest will be skipped.
	//
	// If no rules are defined, the default action will be applied to all requests.
	//
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Rules []MCPRouteAuthorizationRule `json:"rules,omitempty"`
}

// MCPRouteAuthorizationRule defines an authorization rule for MCPRoute based on the MCP authorization spec.
// Reference: https://modelcontextprotocol.io/specification/draft/basic/authorization#scope-challenge-handling
type MCPRouteAuthorizationRule struct {
	// Source defines the authorization source for this rule.
	// If not specified, the rule will match all sources.
	//
	// +kubebuilder:validation:Optional
	Source *MCPAuthorizationSource `json:"source,omitempty"`

	// Target defines the authorization target for this rule.
	// If not specified, the rule will match all targets.
	//
	// +kubebuilder:validation:Optional
	Target *MCPAuthorizationTarget `json:"target,omitempty"`

	// CEL specifies a Common Expression Language (CEL) expression evaluated for this rule.
	// The expression must return a boolean; evaluation errors or non-boolean results
	// are treated as "no match".
	//
	// Example CEL expressions:
	//	* `request.method == "POST"`
	//	* `request.headers["x-custom-header"] == "AllowedValue"`
	//	* `request.mcp.tool in ["toolA", "toolB"]`
	//
	// Available attributes in the CEL expression:
	//
	//	* request.method: HTTP method such as GET or POST. Type: string.
	//	* request.headers: map of headers with lowercased keys, first value only. Type: map[string]string.
	//	* request.headers_all: map of headers with lowercased keys, all values. Type: map[string][]string.
	//	* request.path: request path such as /mcp. Type: string.
	//	* request.auth.jwt.claims: JWT claims when a bearer JWT is present. Type: map[string]any.
	//	* request.auth.jwt.scopes: JWT scopes when a bearer JWT is present. Type: []string.
	//	* request.mcp.method: MCP method such as tools/list or tools/call. Type: string.
	//	* request.mcp.backend: upstream backend name (for example, "kiwi" or "github"). Type: string.
	//	* request.mcp.tool: tool name without backend prefix (for example, "list_issues"). Type: string.
	//	* request.mcp.params: parameters of the MCP method, including keys like "_meta" and "arguments". Type: object.
	//
	// Note: The CEL expression support is experimental, and the attributes
	// available to the expression may change in future releases.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=4096
	// +optional
	CEL *string `json:"cel,omitempty"`

	// Action is the authorization decision for matching requests. If unspecified, defaults to Allow.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=Allow
	// +optional
	Action *egv1a1.AuthorizationAction `json:"action,omitempty"`
}

// MCPAuthorizationTarget defines the target of an authorization rule.
type MCPAuthorizationTarget struct {
	// Tools defines the list of tools this rule applies to.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Tools []ToolCall `json:"tools"`
}

// MCPAuthorizationSource defines the source of an authorization rule.
type MCPAuthorizationSource struct {
	// JWT defines the JWT scopes required for this rule to match.
	//
	// +kubebuilder:validation:Required
	JWT JWTSource `json:"jwt"`

	// TODO: JWTSource can be optional in the future when we support more source types.
}

// JWTSource defines the MCP authorization source for JWT tokens.
// At least one of scopes or claims must be provided.
// Scopes and claims are AND-ed: when both are specified, both sets must match.
//
// +kubebuilder:validation:XValidation:rule="(has(self.scopes) && size(self.scopes) > 0) || (has(self.claims) && size(self.claims) > 0)",message="either scopes or claims must be specified"
type JWTSource struct {
	// Scopes defines the list of JWT scopes required for the rule.
	// If multiple scopes are specified, all scopes must be present in the JWT for the rule to match.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Scopes []egv1a1.JWTScope `json:"scopes,omitempty"`

	// Claims defines the list of JWT claims required for the rule. Each claim must exist on the token
	// and have at least one of the expected values. Use to enforce tenant or subject-based access.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// +optional
	// +kubebuilder:validation:XValidation:rule="!self.exists(c, c.name == 'scope')",message="'scope' claim name is reserved for OAuth scopes"
	Claims []egv1a1.JWTClaim `json:"claims,omitempty"`
}

// ToolCall represents a tool call in the MCP authorization target.
type ToolCall struct {
	// Backend is the name of the backend this tool belongs to.
	//
	// +kubebuilder:validation:Required
	Backend string `json:"backend"`

	// Tool is the name of the tool.
	//
	// +kubebuilder:validation:Required
	Tool string `json:"tool"`
}

// JWKS defines how to obtain JSON Web Key Sets (JWKS) either from a remote HTTP/HTTPS endpoint or from a local source.
// +kubebuilder:validation:XValidation:rule="has(self.remoteJWKS) || has(self.localJWKS)", message="either remoteJWKS or localJWKS must be specified."
// +kubebuilder:validation:XValidation:rule="!(has(self.remoteJWKS) && has(self.localJWKS))", message="remoteJWKS and localJWKS cannot both be specified."
type JWKS struct {
	// RemoteJWKS defines how to fetch and cache JSON Web Key Sets (JWKS) from a remote
	// HTTP/HTTPS endpoint.
	//
	// +optional
	RemoteJWKS *egv1a1.RemoteJWKS `json:"remoteJWKS,omitempty"`

	// LocalJWKS defines how to get the JSON Web Key Sets (JWKS) from a local source.
	//
	// +optional
	LocalJWKS *egv1a1.LocalJWKS `json:"localJWKS,omitempty"`
}

// ProtectedResourceMetadata represents the Protected Resource Metadata	of the MCP server as per RFC 9728.
//
// References:
// * https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#authorization-server-location
// * https://datatracker.ietf.org/doc/html/rfc9728#name-protected-resource-metadata
type ProtectedResourceMetadata struct {
	// Resource is the identifier of the protected resource.
	// This should match the MCPRoute's URL. For example, if the MCPRoute's URL is
	// "https://api.example.com/mcp", the Resource should be "https://api.example.com/mcp".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=uri
	Resource string `json:"resource"`

	// ResourceName is a human-readable name for the protected resource.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=256
	// +optional
	ResourceName *string `json:"resourceName,omitempty"`

	// ScopesSupported defines the minimal set of scopes required for the basic functionality of the MCPRoute.
	// It should avoid broad or overly permissive scopes to prevent clients from requesting tokens with excessive privileges.
	//
	// If an operation requires additional scopes that are not present in the access token, the client will receive a
	// 403 Forbidden response that includes the required scopes in the `scope` field of the `WWW-Authenticate` header.
	// This enables incremental privilege elevation through targeted `WWW-Authenticate: scope="..."` challenges when
	// privileged operations are first attempted.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ScopesSupported []string `json:"scopesSupported,omitempty"`

	// ResourceSigningAlgValuesSupported is a list of JWS signing algorithms supported by the resource server.
	// These algorithms are used in the "alg" field of the JOSE header in signed tokens.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +optional
	ResourceSigningAlgValuesSupported []string `json:"resourceSigningAlgValuesSupported,omitempty"`

	// ResourceDocumentation is a URL that provides human-readable documentation for the resource.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=uri
	// +optional
	ResourceDocumentation *string `json:"resourceDocumentation,omitempty"`

	// ResourcePolicyURI is a URL that points to the resource server's policy document.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=uri
	// +optional
	ResourcePolicyURI *string `json:"resourcePolicyUri,omitempty"`
}
