// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package filterapi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// After the gateway slimming refactor, MCPContentFilterPolicyConfig
// carries only the GlobalDisable kill switch. All in-process knobs
// (PII, cache, breaker, Jira, backends, eval header, wire limits) live
// with the dispatcher service in panacea-agent and are tested there.

// TestPolicyConfig_GlobalDisableDefaultsFalse asserts that a freshly
// constructed policy starts in the safe "filtering active" state. A
// missing or empty ConfigMap must therefore not silently disable the
// filter.
func TestPolicyConfig_GlobalDisableDefaultsFalse(t *testing.T) {
	var p MCPContentFilterPolicyConfig
	require.False(t, p.GlobalDisable, "zero-value policy must have GlobalDisable=false")
}

// TestPolicyConfig_GlobalDisableExplicit asserts the field is
// round-trippable when set explicitly. The struct is intentionally tiny
// so this is mostly a regression guard against an accidental field
// rename or omitempty regression that would silently flip the kill
// switch.
func TestPolicyConfig_GlobalDisableExplicit(t *testing.T) {
	p := MCPContentFilterPolicyConfig{GlobalDisable: true}
	require.True(t, p.GlobalDisable)
}

// TestPolicyConfig_JSONRoundTrip asserts the policy serializes to the
// wire shape the ConfigMap consumes and unmarshals back losslessly.
//
// We exercise the omitempty behavior explicitly: a zero-value policy
// must serialize to an empty object so a "filter still on" ConfigMap
// stays minimal, while an explicitly disabled policy must serialize the
// flag so operators can grep for it.
func TestPolicyConfig_JSONRoundTrip(t *testing.T) {
	t.Run("zero_value_omits_globalDisable", func(t *testing.T) {
		p := MCPContentFilterPolicyConfig{}
		data, err := json.Marshal(p)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(data),
			"zero-value policy should serialize to an empty object thanks to omitempty")

		var got MCPContentFilterPolicyConfig
		require.NoError(t, json.Unmarshal(data, &got))
		require.Equal(t, p, got)
	})

	t.Run("explicit_disable_round_trips", func(t *testing.T) {
		p := MCPContentFilterPolicyConfig{GlobalDisable: true}
		data, err := json.Marshal(p)
		require.NoError(t, err)
		require.JSONEq(t, `{"globalDisable":true}`, string(data))

		var got MCPContentFilterPolicyConfig
		require.NoError(t, json.Unmarshal(data, &got))
		require.Equal(t, p, got)
	})
}
