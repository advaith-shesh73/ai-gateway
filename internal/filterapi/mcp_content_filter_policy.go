// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

// MCPContentFilterPolicyConfig holds the cluster-scoped tunables that
// the gateway reads at runtime from the content-filter-policy
// ConfigMap.
//
// After the gateway slimming refactor the gateway speaks to an external
// content-filter service over HTTP and no longer hosts any of the
// in-process knobs (PII, cache, breaker, Jira, backends, eval header,
// wire limits). All of those policy fields now live with the dispatcher
// service in panacea-agent/services/aigw-content-filter and are loaded
// from that service's own configuration source.
//
// What stays here is the single observable lever that the gateway has
// to honor: a process-wide kill switch every operator team can flip on
// during an incident without touching any MCPGatewayRoute.
//
// Historical note: the type was previously named MCPContentFilterPolicy.
// It was renamed to MCPContentFilterPolicyConfig once the CRD gained a
// string enum called MCPContentFilterPolicy (the policy-kind selector
// used by [MCPContentFilter.Policies]) so the two concepts — "which
// engines should run" (enum) vs. "is filtering globally on" (config
// struct) — have distinct, unambiguous names.
type MCPContentFilterPolicyConfig struct {
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
