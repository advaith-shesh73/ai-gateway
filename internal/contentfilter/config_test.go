// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package contentfilter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerConfig_Validate_MissingAddr(t *testing.T) {
	c := &ServerConfig{Policy: "passthrough"}
	require.ErrorContains(t, c.Validate(), "addr is required")
}

func TestServerConfig_Validate_MissingPolicy(t *testing.T) {
	c := &ServerConfig{Addr: ":9093"}
	require.ErrorContains(t, c.Validate(), "policy is required")
}

func TestServerConfig_Validate_UnknownPolicy(t *testing.T) {
	c := &ServerConfig{Addr: ":9093", Policy: "nonsense"}
	require.ErrorContains(t, c.Validate(), `unknown policy "nonsense"`)
}

func TestServerConfig_Validate_PassthroughOK(t *testing.T) {
	c := &ServerConfig{Addr: ":9093", Policy: "passthrough"}
	require.NoError(t, c.Validate())
}

func TestServerConfig_Validate_EvalRequiresInnerConfig(t *testing.T) {
	c := &ServerConfig{Addr: ":9093", Policy: "eval"}
	// Eval config is empty → evalpolicy.Validate() rejects
	// because endpoint/model are required.
	require.Error(t, c.Validate())
}

func TestServerConfig_Validate_CaseInsensitivePolicyName(t *testing.T) {
	c := &ServerConfig{Addr: ":9093", Policy: "PASSTHROUGH"}
	require.NoError(t, c.Validate(),
		"operators should not be tripped up by case in the policy name")
}

func TestLoadServerConfig_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"addr": ":9200",
		"policy": "passthrough",
		"timeoutSeconds": 5
	}`), 0o600))

	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	require.Equal(t, ":9200", cfg.Addr)
	require.Equal(t, "passthrough", cfg.Policy)
	require.Equal(t, 5, cfg.TimeoutSeconds)
}

func TestLoadServerConfig_MissingFile(t *testing.T) {
	_, err := LoadServerConfig("/does/not/exist.json")
	require.ErrorContains(t, err, "read config")
}

func TestLoadServerConfig_EmptyFileRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(path, []byte(``), 0o600))

	_, err := LoadServerConfig(path)
	require.ErrorContains(t, err, "file is empty")
}

func TestLoadServerConfig_MalformedJSONReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`{`), 0o600))

	_, err := LoadServerConfig(path)
	require.ErrorContains(t, err, "parse config")
}

func TestLoadServerConfig_AppliesDefaultAddr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defaults.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"policy":"passthrough"}`), 0o600))

	cfg, err := LoadServerConfig(path)
	require.NoError(t, err)
	require.Equal(t, ":9093", cfg.Addr,
		"default addr should apply so operators can omit it in the common case")
}

func TestServerConfig_BuildPolicy_Passthrough(t *testing.T) {
	c := &ServerConfig{Addr: ":9093", Policy: "passthrough"}
	p, err := c.BuildPolicy()
	require.NoError(t, err)
	require.Equal(t, "passthrough", p.Name())
}

func TestServerConfig_BuildPolicy_UnknownPolicyErrors(t *testing.T) {
	c := &ServerConfig{Addr: ":9093", Policy: "ghost"}
	_, err := c.BuildPolicy()
	require.ErrorContains(t, err, "unsupported policy")
}
