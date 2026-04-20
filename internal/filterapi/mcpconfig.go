// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

// MCPConfig is the configuration for the MCP listener and routing.
type MCPConfig struct {
	// BackendListenerAddr is the address that speaks plain HTTP and can be used to
	// route to each backend directly without interruption.
	//
	// The listener should only listen on the local interface, and equipped with
	// the HCM filter with the plain header-based routing for each backend based
	// on the [internalapi.MCPBackendHeader] header.
	BackendListenerAddr string `json:"backendListenerAddr"`

	// Routes is the list of routes that this listener can route to.
	Routes []MCPRoute `json:"routes,omitempty"`
}

// MCPRoute is the route configuration for routing to each MCP backend based on the tool name.
type MCPRoute struct {
	// Name is the fully qualified identifier of a MCPRoute.
	// This name is set in [internalapi.MCPRouteHeader] header to identify the route.
	Name MCPRouteName `json:"name"`

	// Backends is the list of backends that this route can route to.
	Backends []MCPBackend `json:"backends"`

	// Authorization is the authorization configuration for this route.
	Authorization *MCPRouteAuthorization `json:"authorization,omitempty"`

	// ForwardHeaders specifies HTTP headers to extract from the incoming request and forward to backend MCP servers.
	ForwardHeaders []string `json:"forwardHeaders,omitempty"`
}

// MCPBackend is the MCP backend configuration.
type MCPBackend struct {
	// Name is the fully qualified identifier of a MCP backend.
	// This name is set in [internalapi.MCPBackendHeader] header to route the request to the specific backend.
	Name MCPBackendName `json:"name"`

	// ToolSelector filters the tools exposed by this backend. If not set, all tools are exposed.
	ToolSelector *MCPToolSelector `json:"toolSelector,omitempty"`

	// ContentFilter configures an external HTTP service that inspects and may
	// rewrite tools/call payloads for this backend. Nil means no content
	// filtering is applied. See MCPContentFilter for semantics.
	ContentFilter *MCPContentFilter `json:"contentFilter,omitempty"`
}

// MCPContentFilter is the runtime representation of an external HTTP content
// filter for a single MCP backend. It mirrors
// [aigv1a1.MCPContentFilter] with primitive types only so it can be
// serialized into the proxy config file.
type MCPContentFilter struct {
	// URL is the HTTP(S) endpoint of the content filter service. Must include
	// a scheme (http:// or https://).
	URL string `json:"url"`

	// Scopes selects the phases at which the filter is invoked. Valid
	// members are "Request" and "Response". At least one is required.
	Scopes []MCPContentFilterScope `json:"scopes"`

	// TimeoutSeconds is the per-invocation timeout for the filter HTTP call.
	// A value of 0 indicates that the default should be used.
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`

	// FailurePolicy controls behaviour when the filter cannot be consulted.
	// An empty value indicates that the default (PassThrough) should be used.
	FailurePolicy MCPContentFilterFailurePolicy `json:"failurePolicy,omitempty"`

	// ForwardHeaders is the case-insensitive list of client HTTP headers
	// forwarded into each filter invocation.
	ForwardHeaders []string `json:"forwardHeaders,omitempty"`

	// Mode selects enforcement vs. shadow evaluation. An empty value
	// is treated as Enforce (the default) by the runtime. See
	// [aigv1a1.MCPContentFilterMode] for the full contract.
	Mode MCPContentFilterMode `json:"mode,omitempty"`

	// Enabled toggles the filter for this backend without removing the
	// configuration. A nil pointer is treated as enabled=true by the
	// runtime (for backwards compatibility with configs that do not
	// carry the field). Setting the pointer to false short-circuits
	// every Request/Response-scope invocation for this backend and
	// reports X-Content-Filter-Status: disabled. Global overrides
	// live on MCPContentFilterPolicy.GlobalDisable.
	Enabled *bool `json:"enabled,omitempty"`

	// ShadowSampleRatePermille bounds shadow-mode invocations in
	// permille (parts per thousand, 0..1000). Zero values are
	// treated as 1000 (fully sampled) by the runtime so existing
	// configs that do not carry the field keep their semantics.
	// Values outside the range are clamped at validation time.
	// Ignored when Mode is not Shadow.
	ShadowSampleRatePermille int32 `json:"shadowSampleRatePermille,omitempty"`
}

// MCPContentFilterScope is the runtime mirror of
// [aigv1a1.MCPContentFilterScope].
type MCPContentFilterScope string

const (
	// MCPContentFilterScopeRequest invokes the filter before the backend call.
	MCPContentFilterScopeRequest MCPContentFilterScope = "Request"
	// MCPContentFilterScopeResponse invokes the filter after the backend call.
	MCPContentFilterScopeResponse MCPContentFilterScope = "Response"
)

// MCPContentFilterFailurePolicy is the runtime mirror of
// [aigv1a1.MCPContentFilterFailurePolicy].
type MCPContentFilterFailurePolicy string

const (
	// MCPContentFilterFailurePolicyPassThrough forwards unmodified payloads
	// when the filter cannot be consulted.
	MCPContentFilterFailurePolicyPassThrough MCPContentFilterFailurePolicy = "PassThrough"
	// MCPContentFilterFailurePolicyFail aborts the tool call when the filter
	// cannot be consulted.
	MCPContentFilterFailurePolicyFail MCPContentFilterFailurePolicy = "Fail"
)

// MCPContentFilterMode is the runtime mirror of
// [aigv1a1.MCPContentFilterMode].
type MCPContentFilterMode string

const (
	// MCPContentFilterModeEnforce applies the filter verdict to the
	// client-visible response. Default when the field is empty.
	MCPContentFilterModeEnforce MCPContentFilterMode = "Enforce"
	// MCPContentFilterModeShadow runs the filter pipeline but always
	// forwards the ORIGINAL body. See [aigv1a1.MCPContentFilterMode]
	// for the full contract.
	MCPContentFilterModeShadow MCPContentFilterMode = "Shadow"
)

// MCPBackendName is the name of the MCP backend.
type MCPBackendName = string

// MCPToolSelector filters tools using include and exclude patterns with exact matches or regular expressions.
type MCPToolSelector struct {
	// Include is a list of tool names to include. Only the specified tools will be available.
	Include []string `json:"include,omitempty"`

	// IncludeRegex is a list of RE2-compatible regular expressions that, when matched, include the tool.
	// Only tools matching these patterns will be available.
	// TODO: regex is almost completely absent in the MCP ecosystem, consider removing this for simplicity.
	IncludeRegex []string `json:"includeRegex,omitempty"`

	// Exclude is a list of tool names to exclude. The specified tools will not be available.
	// Exclude rules take precedence over include rules.
	Exclude []string `json:"exclude,omitempty"`

	// ExcludeRegex is a list of RE2-compatible regular expressions that, when matched, exclude the tool.
	// Tools matching these patterns will not be available. Exclude rules take precedence over include rules.
	ExcludeRegex []string `json:"excludeRegex,omitempty"`
}

// MCPRouteName is the name of the MCP route.
type MCPRouteName = string

// MCPRouteAuthorization defines the authorization configuration for a MCPRoute.
type MCPRouteAuthorization struct {
	// DefaultAction is the action to take when no rules match.
	DefaultAction AuthorizationAction `json:"defaultAction"`

	// Rules defines a list of authorization rules.
	// Requests that match any rule and satisfy the rule's conditions will be allowed.
	// Requests that do not match any rule or fail to satisfy the matched rule's conditions will be denied.
	// If no rules are defined, all requests will be denied.
	Rules []MCPRouteAuthorizationRule `json:"rules,omitempty"`

	// ResourceMetadataURL is the URI of the OAuth Protected Resource Metadata document for this route.
	// This is used to populate the WWW-Authenticate header when scope-based authorization fails.
	ResourceMetadataURL string `json:"resourceMetadataURL,omitempty"`
}

type AuthorizationAction string

const (
	// AuthorizationActionAllow is the action to allow the request.
	AuthorizationActionAllow AuthorizationAction = "Allow"
	// AuthorizationActionDeny is the action to deny the request.
	AuthorizationActionDeny AuthorizationAction = "Deny"
)

// MCPRouteAuthorizationRule defines an authorization rule for MCPRoute based on the MCP authorization spec.
// Reference: https://modelcontextprotocol.io/specification/draft/basic/authorization#scope-challenge-handling
type MCPRouteAuthorizationRule struct {
	// Action is the action to take when the rule matches.
	Action AuthorizationAction `json:"action"`

	// Source defines the authorization source for this rule.
	// If not specified, the rule will match all sources.
	Source *MCPAuthorizationSource `json:"source,omitempty"`

	// Target defines the authorization target for this rule.
	// If not specified, the rule will match all targets.
	Target *MCPAuthorizationTarget `json:"target,omitempty"`

	// CEL specifies a Common Expression Language (CEL) expression for this rule.
	// The expression must evaluate to true for the rule to match.
	// If empty, no CEL condition is applied.
	CEL *string `json:"cel,omitempty"`
}

type MCPAuthorizationTarget struct {
	// Tools defines the list of tools this rule applies to.
	Tools []ToolCall `json:"tools"`
}

type MCPAuthorizationSource struct {
	// JWT defines the JWT scopes required for this rule to match.
	JWT JWTSource `json:"jwt"`
}

type JWTSource struct {
	// Scopes defines the list of JWT scopes required for the rule.
	// If multiple scopes are specified, all scopes must be present in the JWT for the rule to match.
	Scopes []string `json:"scopes,omitempty"`

	// Claims defines the list of JWT claims required for the rule. Each claim must exist on the token
	// and have at least one of the expected values.
	Claims []JWTClaim `json:"claims,omitempty"`
}

type JWTClaim struct {
	// Name is the name of the claim, supports dotted paths for nested claims.
	Name string `json:"name"`

	// ValueType indicates whether the claim value is expected to be a string or string array.
	ValueType JWTClaimValueType `json:"valueType"`

	// Values are the values that the claim must match.
	// If the claim is a string type, the specified value must match exactly.
	// If the claim is a string array type, the specified value must match one of the values in the array.
	// If multiple values are specified, one of the values must match for the rule to match.
	Values []string `json:"values"`
}

type JWTClaimValueType string

const (
	JWTClaimValueTypeString      JWTClaimValueType = "String"
	JWTClaimValueTypeStringArray JWTClaimValueType = "StringArray"
)

type ToolCall struct {
	// Backend is the name of the backend this tool belongs to.
	Backend string `json:"backend"`

	// Tool is the name of the tool.
	Tool string `json:"tool"`
}
