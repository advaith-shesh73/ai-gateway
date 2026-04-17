// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package contentfilter

import (
	"fmt"
	"os"
	"strings"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter/evalpolicy"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// ServerConfig captures the runtime knobs of a content-filter
// service instance. Loaded once at startup from the file or
// ConfigMap referenced by --config; reloads require a pod restart
// (the service is stateless so rolling restart is cheap).
//
// The config is split by policy kind: the top-level Policy field
// selects which implementation handles requests, and the
// implementation's own block carries its knobs. This keeps the
// schema extensible — adding a new policy means a new field on
// ServerConfig and a new top-level value, without reshuffling
// existing operators' configs.
type ServerConfig struct {
	// Addr is the listen address for the HTTP server. Typically
	// ":9093"; set via --addr to override.
	Addr string `json:"addr"`
	// Policy picks the filter implementation. Valid values:
	// "eval" (the PR 95 port, see [evalpolicy]) and
	// "passthrough" (ActionPass for everything; for integration
	// tests). Unknown values are rejected at load time.
	Policy string `json:"policy"`
	// TimeoutSeconds caps per-invocation wall time at the server
	// boundary; 0 uses [defaultInvocationTimeout]. Must be <= the
	// gateway's filter timeout to give the gateway slack for its
	// own FailurePolicy decision.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// Eval carries the config block for the PR 95 port. Ignored
	// when Policy != "eval".
	Eval evalpolicy.Config `json:"eval"`
}

// Validate checks invariants that cannot be expressed in JSON schema
// alone. Callers MUST invoke it after loading; the server will
// otherwise discover the problem at first request time.
func (c *ServerConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.Addr == "" {
		return fmt.Errorf("addr is required")
	}
	switch strings.ToLower(c.Policy) {
	case "eval":
		return c.Eval.Validate()
	case "passthrough":
		return nil
	case "":
		return fmt.Errorf("policy is required (one of: eval, passthrough)")
	default:
		return fmt.Errorf("unknown policy %q (expected one of: eval, passthrough)", c.Policy)
	}
}

// LoadServerConfig reads path, decodes JSON, applies defaults, and
// validates the result. Returns a descriptive error on I/O failure,
// parse failure, or validation failure. The zero-length-file case
// is a user error: we do not silently default to passthrough
// because a typo in the ConfigMap mount should surface loudly.
func LoadServerConfig(path string) (*ServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("read config %q: file is empty", path)
	}
	var cfg ServerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	return &cfg, nil
}

// applyDefaults fills in fields the operator left unset so Validate
// sees a fully-specified config. Only safe, conservative defaults
// go here — anything that has an operational consequence (policy
// selection, LLM endpoint) stays mandatory.
func (c *ServerConfig) applyDefaults() {
	if c.Addr == "" {
		c.Addr = ":9093"
	}
	c.Eval.ApplyDefaults()
}

// BuildPolicy instantiates the Policy referenced by c.Policy. Must
// be called after Validate.
func (c *ServerConfig) BuildPolicy() (Policy, error) {
	switch strings.ToLower(c.Policy) {
	case "eval":
		return evalpolicy.New(c.Eval)
	case "passthrough":
		return PassThroughPolicy{}, nil
	default:
		return nil, fmt.Errorf("unsupported policy %q", c.Policy)
	}
}
