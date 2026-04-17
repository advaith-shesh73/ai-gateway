// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCircuitBreakerBackoff_DefaultsFillIn checks the defaulting
// logic applied to the BackoffMultiplier and MaxResetTimeout fields.
func TestCircuitBreakerBackoff_DefaultsFillIn(t *testing.T) {
	cfg := CircuitBreakerConfig{
		ResetTimeout: 10 * time.Second,
	}.withDefaults()
	require.Equal(t, 2.0, cfg.BackoffMultiplier)
	require.Equal(t, 100*time.Second, cfg.MaxResetTimeout) // 10x default
}

func TestCircuitBreakerBackoff_MultiplierClampsUp(t *testing.T) {
	cfg := CircuitBreakerConfig{
		ResetTimeout:      time.Second,
		BackoffMultiplier: 0.5, // invalid: would DECREASE cooldown
	}.withDefaults()
	require.Equal(t, 2.0, cfg.BackoffMultiplier)
}

func TestCircuitBreakerBackoff_MaxResetTimeoutClampsUp(t *testing.T) {
	cfg := CircuitBreakerConfig{
		ResetTimeout:    5 * time.Second,
		MaxResetTimeout: 1 * time.Second, // invalid: cap < base
	}.withDefaults()
	require.Equal(t, 5*time.Second, cfg.MaxResetTimeout)
}

// TestCircuitBreakerBackoff_GrowsOnConsecutiveHalfOpenFailures drives
// the full backoff curve: trip, probe, fail, probe, fail, … verifying
// the cooldown doubles at each step and plateaus at MaxResetTimeout.
func TestCircuitBreakerBackoff_GrowsOnConsecutiveHalfOpenFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	cfg := CircuitBreakerConfig{
		FailureThreshold:  2,
		ResetTimeout:      time.Second,
		HalfOpenMaxCalls:  1,
		BackoffMultiplier: 2.0,
		MaxResetTimeout:   8 * time.Second,
	}
	br := NewCircuitBreakerWithClock("test", cfg, clock, nil, nil)

	// Initial trip from CLOSED: use base cooldown (1s).
	br.RecordFailure()
	br.RecordFailure()
	require.Equal(t, CircuitOpen, br.State())
	require.Equal(t, time.Second, br.CurrentCooldown())

	// Probe #1: must wait base=1s.
	require.False(t, br.Allow())
	now = now.Add(time.Second)
	require.True(t, br.Allow())
	require.Equal(t, CircuitHalfOpen, br.State())
	// Probe #1 fails → grow to 2s and re-open.
	br.RecordFailure()
	require.Equal(t, CircuitOpen, br.State())
	require.Equal(t, 2*time.Second, br.CurrentCooldown())

	// Probe #2: must wait 2s.
	require.False(t, br.Allow())
	now = now.Add(time.Second) // only 1s elapsed
	require.False(t, br.Allow())
	now = now.Add(time.Second) // now 2s elapsed
	require.True(t, br.Allow())
	// Probe #2 fails → grow to 4s.
	br.RecordFailure()
	require.Equal(t, 4*time.Second, br.CurrentCooldown())

	// Probe #3 must wait 4s.
	now = now.Add(4 * time.Second)
	require.True(t, br.Allow())
	// Probe #3 fails → grow to 8s (hits cap).
	br.RecordFailure()
	require.Equal(t, 8*time.Second, br.CurrentCooldown())

	// Probe #4 must wait 8s AND the cooldown stays at 8s (cap).
	now = now.Add(8 * time.Second)
	require.True(t, br.Allow())
	br.RecordFailure()
	require.Equal(t, 8*time.Second, br.CurrentCooldown(),
		"cooldown must not exceed MaxResetTimeout")
}

// TestCircuitBreakerBackoff_ResetsOnSuccess verifies that a recovered
// backend resets the backoff curve. This is the property that keeps
// a backend that flaps months apart from inheriting a 10x cooldown
// on every subsequent degradation.
func TestCircuitBreakerBackoff_ResetsOnSuccess(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	cfg := CircuitBreakerConfig{
		FailureThreshold:  1,
		ResetTimeout:      time.Second,
		HalfOpenMaxCalls:  1,
		BackoffMultiplier: 2.0,
		MaxResetTimeout:   time.Hour,
	}
	br := NewCircuitBreakerWithClock("test", cfg, clock, nil, nil)

	// Trip, fail probe twice to grow cooldown.
	br.RecordFailure()
	now = now.Add(time.Second)
	require.True(t, br.Allow())
	br.RecordFailure()
	require.Equal(t, 2*time.Second, br.CurrentCooldown())
	now = now.Add(2 * time.Second)
	require.True(t, br.Allow())
	br.RecordFailure()
	require.Equal(t, 4*time.Second, br.CurrentCooldown())

	// Recovered probe.
	now = now.Add(4 * time.Second)
	require.True(t, br.Allow())
	br.RecordSuccess()
	require.Equal(t, CircuitClosed, br.State())
	require.Equal(t, time.Second, br.CurrentCooldown(),
		"cooldown must reset to base on successful recovery")
}
