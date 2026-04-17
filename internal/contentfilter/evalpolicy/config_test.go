// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_ApplyDefaults_FillsUnsetFields(t *testing.T) {
	c := Config{}
	c.ApplyDefaults()
	require.Equal(t, defaultEndpoint, c.Endpoint)
	require.Equal(t, defaultModel, c.Model)
	require.Equal(t, defaultAPIKeyEnv, c.APIKeyEnv)
	require.Equal(t, defaultTimeoutSeconds, c.TimeoutSeconds)
	require.Equal(t, defaultTicketHeader, c.TicketHeader)
}

func TestConfig_ApplyDefaults_PreservesExplicitValues(t *testing.T) {
	c := Config{
		Endpoint:       "http://x",
		Model:          "my-model",
		APIKeyEnv:      "MYKEY",
		TimeoutSeconds: 30,
		TicketHeader:   "X-Foo",
	}
	c.ApplyDefaults()
	require.Equal(t, "http://x", c.Endpoint)
	require.Equal(t, "my-model", c.Model)
	require.Equal(t, "MYKEY", c.APIKeyEnv)
	require.Equal(t, 30, c.TimeoutSeconds)
	require.Equal(t, "X-Foo", c.TicketHeader)
}

func TestConfig_Validate(t *testing.T) {
	t.Run("fails on empty endpoint", func(t *testing.T) {
		c := Config{Model: "m", TimeoutSeconds: 1}
		require.ErrorContains(t, c.Validate(), "endpoint is required")
	})
	t.Run("fails on non-http endpoint", func(t *testing.T) {
		c := Config{Endpoint: "grpc://x", Model: "m", TimeoutSeconds: 1}
		require.ErrorContains(t, c.Validate(), "http(s)")
	})
	t.Run("fails on empty model", func(t *testing.T) {
		c := Config{Endpoint: "https://x", TimeoutSeconds: 1}
		require.ErrorContains(t, c.Validate(), "model is required")
	})
	t.Run("fails on non-positive timeout", func(t *testing.T) {
		c := Config{Endpoint: "https://x", Model: "m", TimeoutSeconds: 0}
		require.ErrorContains(t, c.Validate(), "timeoutSeconds")
	})
	t.Run("fails on negative temperature", func(t *testing.T) {
		c := Config{Endpoint: "https://x", Model: "m", TimeoutSeconds: 1, Temperature: -1}
		require.ErrorContains(t, c.Validate(), "temperature")
	})
	t.Run("passes with minimum valid config", func(t *testing.T) {
		c := Config{Endpoint: "https://x", Model: "m", TimeoutSeconds: 1}
		require.NoError(t, c.Validate())
	})
}

func TestConfig_ResolveAPIKey(t *testing.T) {
	t.Run("prefers env var when set", func(t *testing.T) {
		t.Setenv("MY_KEY", "envvalue")
		c := Config{APIKeyEnv: "MY_KEY"}
		require.Equal(t, "envvalue", c.resolveAPIKey())
	})
	t.Run("falls back to file when env empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(path, []byte("filekey\n"), 0o600))

		t.Setenv("MY_KEY_2", "")
		c := Config{APIKeyEnv: "MY_KEY_2", APIKeyFile: path}
		require.Equal(t, "filekey", c.resolveAPIKey(),
			"whitespace must be trimmed so operators can 'echo > file' safely")
	})
	t.Run("returns empty when neither source available", func(t *testing.T) {
		c := Config{APIKeyEnv: "NONEXISTENT", APIKeyFile: "/nope/nope"}
		require.Empty(t, c.resolveAPIKey())
	})
	t.Run("file error falls through quietly (safe-redaction takes over)", func(t *testing.T) {
		c := Config{APIKeyFile: "/does/not/exist"}
		require.Empty(t, c.resolveAPIKey())
	})
}

func TestConfig_ToolFilterSet_EmptyConfigYieldsEmptySet(t *testing.T) {
	c := Config{}
	require.Empty(t, c.toolFilterSet())
}

func TestConfig_ToolFilterSet_BuildsSetAndSkipsEmpty(t *testing.T) {
	c := Config{FilteredTools: []string{"a", "", "b", "a"}}
	set := c.toolFilterSet()
	require.Contains(t, set, "a")
	require.Contains(t, set, "b")
	require.NotContains(t, set, "")
	require.Len(t, set, 2)
}
