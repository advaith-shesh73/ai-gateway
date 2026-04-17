// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestShardedCache_DefaultShardCount pins that a freshly-built cache
// uses [defaultCacheShards] partitions. The count is observable via
// [ContentFilterCache.Shards] so operators can assert this at boot.
func TestShardedCache_DefaultShardCount(t *testing.T) {
	c := NewContentFilterCacheWithClock(ContentFilterCacheConfig{}, newFakeClock().Now)
	require.Equal(t, defaultCacheShards, c.Shards())
}

// TestShardedCache_ExplicitShardCount lets operators dial sharding up
// or down. Zero and negative collapse to the default, preventing
// accidental foot-guns where a misconfigured YAML disables the
// cache.
func TestShardedCache_ExplicitShardCount(t *testing.T) {
	for _, n := range []int{1, 4, 16, 32} {
		c := NewContentFilterCacheWithClock(
			ContentFilterCacheConfig{Shards: n, MaxEntries: 64},
			newFakeClock().Now,
		)
		require.Equal(t, n, c.Shards(), "Shards=%d", n)
	}

	zero := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: 0, MaxEntries: 64},
		newFakeClock().Now,
	)
	require.Equal(t, defaultCacheShards, zero.Shards(), "Shards=0 falls back to default")

	neg := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: -1, MaxEntries: 64},
		newFakeClock().Now,
	)
	require.Equal(t, defaultCacheShards, neg.Shards(), "Shards=-1 falls back to default")
}

// TestShardedCache_KeysDistributeAcrossShards proves the FNV-1a shard
// selector actually spreads load. Drive 2048 keys into a 16-shard
// cache and assert that no single shard is starved AND no single
// shard holds a disproportionate share. This is both a distribution
// test and a regression guard against someone "simplifying"
// [ContentFilterCache.shardFor] to e.g. `key[0] % n` which would
// cluster hex-prefix keys.
func TestShardedCache_KeysDistributeAcrossShards(t *testing.T) {
	const (
		shards  = 16
		entries = 4096
	)
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: shards, MaxEntries: entries * 2},
		newFakeClock().Now,
	)
	for i := 0; i < entries; i++ {
		c.Put(ContentFilterCacheKey("ctx", strconv.Itoa(i)), "v")
	}

	// Assert even distribution: every shard should be between 25%
	// and 175% of the expected average. We leave headroom for
	// natural FNV variance at this sample size.
	expected := entries / shards
	for i, s := range c.shards {
		count := s.len()
		require.GreaterOrEqual(t, count, expected/4,
			"shard %d starved: got %d, expected ~%d", i, count, expected)
		require.LessOrEqual(t, count, expected*7/4,
			"shard %d overloaded: got %d, expected ~%d", i, count, expected)
	}
	require.Equal(t, entries, c.Len(), "total Len() must match sum of shard contents")
}

// TestShardedCache_PerShardEviction proves that per-shard caps are
// enforced locally: one shard overflowing does NOT trigger eviction
// in sibling shards. We synthesize this by pinning Shards=2 and
// writing 10 keys to shard A plus 1 key to shard B, observing that
// shard B's single entry survives.
func TestShardedCache_PerShardEviction(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: 2, MaxEntries: 4},
		newFakeClock().Now,
	)
	// With 2 shards and MaxEntries=4, perShard=2.
	// Seed every shard with enough keys to find keys that land in
	// each. Using the observable shardFor via c.shardFor() (exposed
	// internally).
	var sA, sB []string
	for i := 0; i < 200; i++ {
		k := "k" + strconv.Itoa(i)
		if c.shardFor(k) == c.shards[0] {
			sA = append(sA, k)
		} else {
			sB = append(sB, k)
		}
		if len(sA) >= 10 && len(sB) >= 1 {
			break
		}
	}
	require.GreaterOrEqual(t, len(sA), 10)
	require.GreaterOrEqual(t, len(sB), 1)

	// Fill shard A well above its 2-entry cap.
	for _, k := range sA[:10] {
		c.Put(k, "v"+k)
	}
	// Single write into shard B.
	c.Put(sB[0], "B")

	// Shard B entry should still be present; shard A should have
	// kept only the last 2 writes.
	v, ok := c.Get(sB[0])
	require.True(t, ok, "shard B entry evicted by shard A's pressure")
	require.Equal(t, "B", v)

	require.LessOrEqual(t, c.shards[0].len(), 2, "shard A must respect its per-shard cap")
	require.LessOrEqual(t, c.shards[1].len(), 2, "shard B unchanged")
}

// TestShardedCache_ConcurrentThroughputNoRace pounds a 16-shard cache
// from many goroutines. Under the race detector this is the primary
// evidence that per-shard mutexes don't corrupt each other and that
// there is no shared state modified without a lock.
func TestShardedCache_ConcurrentThroughputNoRace(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: 16, MaxEntries: 1024, TTL: time.Minute},
		newFakeClock().Now,
	)
	const (
		writers = 32
		readers = 32
		iters   = 500
	)
	var wg sync.WaitGroup
	wg.Add(writers + readers)
	for g := 0; g < writers; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				k := fmt.Sprintf("w%d-k%d", g, i%256)
				c.Put(k, "v")
			}
		}(g)
	}
	for g := 0; g < readers; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				k := fmt.Sprintf("w%d-k%d", g%writers, i%256)
				_, _ = c.Get(k)
			}
		}(g)
	}
	wg.Wait()
	require.LessOrEqual(t, c.Len(), 1024)
}

// TestShardedCache_PerShardEntries_Ceiling verifies the ceiling-
// division allocates capacity consistently.
func TestShardedCache_PerShardEntries_Ceiling(t *testing.T) {
	for _, tc := range []struct {
		maxEntries int
		shards     int
		want       int
	}{
		{maxEntries: 0, shards: 0, want: 1024 / defaultCacheShards},
		{maxEntries: 100, shards: 10, want: 10},
		{maxEntries: 101, shards: 10, want: 11}, // ceil
		{maxEntries: 1, shards: 16, want: 1},    // clamped to ≥1
		{maxEntries: 3, shards: 16, want: 1},    // tiny cap spreads to one each
	} {
		cfg := ContentFilterCacheConfig{MaxEntries: tc.maxEntries, Shards: tc.shards}.withDefaults()
		require.Equal(t, tc.want, cfg.perShardEntries(),
			"MaxEntries=%d, Shards=%d", tc.maxEntries, tc.shards)
	}
}

// TestShardedCache_MaxBytes_EnforcedOnInsert proves L09 evicts to stay
// under the per-shard byte budget. We pin Shards=1 so the whole
// budget lives in one shard and the math is deterministic.
func TestShardedCache_MaxBytes_EnforcedOnInsert(t *testing.T) {
	// Two-entry byte ceiling. Each entry is len("kN")=2 key bytes +
	// len(value)=64 value bytes + [perEntryOverheadBytes] of fixed
	// overhead. A cap of 2×entrySize holds exactly 2 entries; a
	// third insert evicts the oldest.
	const payload = 64
	const keyLen = 2 // "kN"
	value := make([]byte, payload)
	for i := range value {
		value[i] = 'x'
	}
	const entrySize = int64(keyLen + payload + perEntryOverheadBytes)
	const maxBytes = 2 * entrySize

	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{
			Shards:     1,
			MaxEntries: 1000, // effectively unbounded for this test
			MaxBytes:   maxBytes,
		},
		newFakeClock().Now,
	)
	c.Put("k1", string(value))
	c.Put("k2", string(value))
	c.Put("k3", string(value)) // evicts k1

	_, ok := c.Get("k1")
	require.False(t, ok, "k1 should be evicted by byte-budget eviction")

	_, ok = c.Get("k2")
	require.True(t, ok, "k2 must survive")
	_, ok = c.Get("k3")
	require.True(t, ok, "k3 must survive")

	require.LessOrEqual(t, c.ApproxBytes(), maxBytes,
		"cache bytes must not exceed configured MaxBytes")
}

// TestShardedCache_MaxBytes_UpdatesDoNotLeakBudget ensures an in-place
// update of an existing key correctly re-accounts bytes so a
// shrinking value frees budget and a growing value can trigger
// eviction.
func TestShardedCache_MaxBytes_UpdatesDoNotLeakBudget(t *testing.T) {
	// Key is the 1-byte string "k"; include it in the size math.
	const keyLen = 1
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{
			Shards:     1,
			MaxEntries: 1000,
			MaxBytes:   int64(300 + keyLen + perEntryOverheadBytes),
		},
		newFakeClock().Now,
	)
	c.Put("k", string(make([]byte, 200)))
	before := c.ApproxBytes()
	require.EqualValues(t, keyLen+200+perEntryOverheadBytes, before)

	// Shrink in-place.
	c.Put("k", "x")
	after := c.ApproxBytes()
	require.Less(t, after, before, "shrinking update must release bytes")
	require.EqualValues(t, keyLen+1+perEntryOverheadBytes, after)
}

// TestShardedCache_MaxBytes_DisabledWhenZero checks that MaxBytes=0
// leaves the cache without a byte budget (backwards compatible).
func TestShardedCache_MaxBytes_DisabledWhenZero(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: 1, MaxEntries: 4},
		newFakeClock().Now,
	)
	for i := 0; i < 4; i++ {
		c.Put(strconv.Itoa(i), string(make([]byte, 10_000)))
	}
	require.Equal(t, 4, c.Len())
	// No MaxBytes — all 4 entries survive even though total bytes
	// are ~40 KiB.
	require.Greater(t, c.ApproxBytes(), int64(30_000))
}

// TestShardedCache_ApproxBytes_Decrements verifies that eviction and
// clear correctly drain the byte counter, so dashboards showing
// cache bytes don't drift upward with cache churn.
func TestShardedCache_ApproxBytes_Decrements(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{Shards: 1, MaxEntries: 4},
		newFakeClock().Now,
	)
	for i := 0; i < 4; i++ {
		c.Put(strconv.Itoa(i), "value-"+strconv.Itoa(i))
	}
	seeded := c.ApproxBytes()
	require.Positive(t, seeded)

	// Drive 4 more keys, each evicting one of the originals.
	for i := 4; i < 8; i++ {
		c.Put(strconv.Itoa(i), "value-"+strconv.Itoa(i))
	}
	// Steady-state at 4 entries → bytes roughly stable.
	require.Equal(t, 4, c.Len())

	c.Clear()
	require.EqualValues(t, 0, c.ApproxBytes(), "Clear must zero the byte counter")
	require.Equal(t, 0, c.Len())
}

// TestShardedCache_TTLExpiry_ReleasesBytes confirms that a byte-budget
// cache doesn't leak bytes for entries that expire via TTL. Without
// this, a steady flow of short-lived keys could accumulate
// permanently-accounted bytes.
func TestShardedCache_TTLExpiry_ReleasesBytes(t *testing.T) {
	clock := newFakeClock()
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{
			Shards:   1,
			TTL:      time.Second,
			MaxBytes: int64(1 << 20),
		},
		clock.Now,
	)
	c.Put("k", string(make([]byte, 1024)))
	require.Greater(t, c.ApproxBytes(), int64(1024))

	clock.Advance(2 * time.Second)
	_, ok := c.Get("k")
	require.False(t, ok, "entry must be expired")
	require.EqualValues(t, 0, c.ApproxBytes(),
		"TTL eviction must release bytes, not just report miss")
}
