// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- TestLRUCacheBasic --------------------------------------------------

func TestCache_HitThenMiss(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 4, TTL: time.Minute},
		newFakeClock().Now,
	)
	c.Put("k", "v")

	v, ok := c.Get("k")
	require.True(t, ok)
	require.Equal(t, "v", v)

	_, ok = c.Get("missing")
	require.False(t, ok)
}

func TestCache_KeyForIsContentHashed(t *testing.T) {
	k1 := ContentFilterCacheKey("default:tool", "hello")
	k2 := ContentFilterCacheKey("default:tool", "hello")
	k3 := ContentFilterCacheKey("other:tool", "hello")
	require.Equal(t, k1, k2, "same inputs must produce same hash")
	require.NotEqual(t, k1, k3, "different context must change hash")
	require.Len(t, k1, 64, "SHA-256 hex digest is 64 chars")
}

func TestCache_EmptyContextDifferentFromNonempty(t *testing.T) {
	require.NotEqual(t,
		ContentFilterCacheKey("", "hi"),
		ContentFilterCacheKey("x", "hi"),
	)
}

func TestCache_KeyCollisionResistantToConcatenation(t *testing.T) {
	// The "\x00" separator guarantees ("ab", "c") hashes differently
	// from ("a", "bc") — important because otherwise two different
	// (context, text) pairs could legitimately share a cache row.
	require.NotEqual(t,
		ContentFilterCacheKey("ab", "c"),
		ContentFilterCacheKey("a", "bc"),
	)
}

// TestCache_KeyMatchesPythonReference pins the hash output to the Python
// sidecar's values so two nodes running the same policy produce the same
// cache keys. Computed from hashlib.sha256(b"<ctx>\x00<text>").hexdigest().
func TestCache_KeyMatchesPythonReference(t *testing.T) {
	require.Equal(t,
		"e0ed65a4beaa04ecc35e10b35adc1a6a3ca043f3951c2d00974c70502a4a3e69",
		ContentFilterCacheKey("default:tool", "hello"),
	)
	require.Equal(t,
		"e6908025cd50ce380feecfeaedb70ba2c2f701cc5e314b7b70ef5e1c04b0ec58",
		ContentFilterCacheKey("", "hi"),
	)
}

// TestCache_TenantKeyIsolatesRoutes is the core guarantee L06 exists
// to provide: two different routes that happen to use the same
// backend + piiContext + text MUST produce different cache rows so
// they cannot leak each other's redactions, even if a misconfigured
// piiContext string lets them share a bucket otherwise.
func TestCache_TenantKeyIsolatesRoutes(t *testing.T) {
	base := func(route, backend string) string {
		return ContentFilterCacheKeyTenant("Response|supportgpt:search", route, backend, "tenant PII")
	}
	// Snapshot one call so the determinism check compares two distinct
	// string values (the assertion library otherwise flags an x==x
	// comparison, even though semantically we are asserting that two
	// independent invocations are stable).
	ra := base("route-a", "supportgpt")
	require.Equal(t, ra, base("route-a", "supportgpt"),
		"same (route, backend) must be deterministic")
	require.NotEqual(t, ra, base("route-b", "supportgpt"),
		"different routes must not share a row")
	require.NotEqual(t, ra, base("route-a", "nurag"),
		"different backends must not share a row")
	require.NotEqual(t, base("", ""), ra,
		"empty-tenant key must differ from a populated tenant")
}

// TestCache_TenantKeyCollisionFreeWithPlainKey proves the 3-null-byte
// separator placement makes the tenant form safely distinct from the
// plain 1-null-byte form even for cleverly-concatenated inputs. If
// this ever regresses we risk two different calls silently sharing a
// cache row.
func TestCache_TenantKeyCollisionFreeWithPlainKey(t *testing.T) {
	// Plain key hashes (ctx || \0 || text).
	plain := ContentFilterCacheKey("a\x00b\x00c", "d")
	// Tenant key hashes (ctx || \0 || route || \0 || backend || \0 || text).
	tenant := ContentFilterCacheKeyTenant("a", "b", "c", "d")
	// The tenant form still uses the 3-null-byte layout, so these
	// two keys must differ — same byte sequence fed through the hash,
	// but the caller is asking different questions.
	require.NotEqual(t, plain, tenant,
		"plain and tenant keys must never collide on shared byte sequences")
}

// TestBuildPIIContext_Canonical ensures the canonical format is stable
// (operators grep for `scope=Response|route=supportgpt-main` in logs).
// Changing this format is a breaking change for existing dashboards.
func TestBuildPIIContext_Canonical(t *testing.T) {
	require.Equal(t,
		"Response|supportgpt-main|supportgpt|tools/call",
		BuildPIIContext(ScopeResponse, "supportgpt-main", "supportgpt", "tools/call"),
	)
	require.Equal(t,
		"Request|||",
		BuildPIIContext(ScopeRequest, "", "", ""),
		"empty fields must render as empty segments, not be dropped",
	)
}

func TestCache_PutOverwrites(t *testing.T) {
	c := NewContentFilterCacheWithClock(ContentFilterCacheConfig{}, newFakeClock().Now)
	c.Put("k", "v1")
	c.Put("k", "v2")

	v, ok := c.Get("k")
	require.True(t, ok)
	require.Equal(t, "v2", v)
}

// --- TestLRUCacheTTL ----------------------------------------------------

func TestCache_EntryExpiresAfterTTL(t *testing.T) {
	clock := newFakeClock()
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{TTL: 10 * time.Second},
		clock.Now,
	)
	c.Put("k", "v")

	clock.Advance(5 * time.Second)
	v, ok := c.Get("k")
	require.True(t, ok, "within TTL — still a hit")
	require.Equal(t, "v", v)

	clock.Advance(6 * time.Second) // total 11s > 10s ttl
	_, ok = c.Get("k")
	require.False(t, ok, "past TTL — miss")
}

func TestCache_ExpiredEntryIsEvictedOnGet(t *testing.T) {
	clock := newFakeClock()
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{TTL: 10 * time.Second},
		clock.Now,
	)
	c.Put("k", "v")
	clock.Advance(11 * time.Second)
	_, _ = c.Get("k")
	require.Equal(t, 0, c.Len(), "expired entry must be removed, not just reported missing")
}

// --- TestLRUCacheEviction ----------------------------------------------

func TestCache_EvictsOldestWhenFull(t *testing.T) {
	// Deterministic eviction ordering only holds when every key maps
	// to the same shard; pin Shards=1 so this test exercises the
	// per-shard LRU discipline directly.
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 3, Shards: 1},
		newFakeClock().Now,
	)
	c.Put("a", "1")
	c.Put("b", "2")
	c.Put("c", "3")
	c.Put("d", "4") // evicts "a"

	_, ok := c.Get("a")
	require.False(t, ok)
	for k, want := range map[string]string{"b": "2", "c": "3", "d": "4"} {
		v, ok := c.Get(k)
		require.True(t, ok, "key %q expected to still be present", k)
		require.Equal(t, want, v)
	}
}

func TestCache_GetPromotesToMostRecent(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 3, Shards: 1},
		newFakeClock().Now,
	)
	c.Put("a", "1")
	c.Put("b", "2")
	c.Put("c", "3")

	_, _ = c.Get("a") // promotes "a" to MRU
	c.Put("d", "4")   // must evict oldest, now "b"

	v, ok := c.Get("a")
	require.True(t, ok)
	require.Equal(t, "1", v)

	_, ok = c.Get("b")
	require.False(t, ok, "b should have been evicted, not a")
}

func TestCache_PutExistingKeyPromotes(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 3, Shards: 1},
		newFakeClock().Now,
	)
	c.Put("a", "1")
	c.Put("b", "2")
	c.Put("c", "3")
	c.Put("a", "1_new") // updates + promotes
	c.Put("d", "4")     // must evict oldest = "b"

	_, ok := c.Get("b")
	require.False(t, ok)

	v, ok := c.Get("a")
	require.True(t, ok)
	require.Equal(t, "1_new", v)
}

func TestCache_LenReportsCurrentSize(t *testing.T) {
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 10},
		newFakeClock().Now,
	)
	require.Equal(t, 0, c.Len())
	for i := 0; i < 5; i++ {
		c.Put(strconv.Itoa(i), "x")
	}
	require.Equal(t, 5, c.Len())
}

func TestCache_ClearDropsEverything(t *testing.T) {
	c := NewContentFilterCacheWithClock(ContentFilterCacheConfig{}, newFakeClock().Now)
	c.Put("a", "1")
	c.Clear()
	require.Equal(t, 0, c.Len())
	_, ok := c.Get("a")
	require.False(t, ok)
}

func TestCacheConfig_Defaults(t *testing.T) {
	cfg := ContentFilterCacheConfig{}.withDefaults()
	require.Equal(t, 1024, cfg.MaxEntries)
	require.Equal(t, 15*time.Minute, cfg.TTL)
	require.Equal(t, defaultCacheShards, cfg.Shards)
	require.EqualValues(t, 0, cfg.MaxBytes, "byte budget disabled by default")
}

// --- Concurrency guards (Go-only; Python has no analog) -----------------

func TestCache_ConcurrentPutGet_NoRace(t *testing.T) {
	// Pounding the cache from many goroutines under `go test -race` is
	// the primary guard that the mutex wraps every critical section.
	c := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 64, TTL: time.Minute},
		newFakeClock().Now,
	)

	const writers = 16
	const readers = 16
	const iters = 500
	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for g := 0; g < writers; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				k := strconv.Itoa((g*iters + i) % 128)
				c.Put(k, "v"+k)
			}
		}(g)
	}
	for g := 0; g < readers; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				k := strconv.Itoa((g*iters + i) % 128)
				_, _ = c.Get(k)
			}
		}(g)
	}
	wg.Wait()

	// Cache is bounded; post-condition is that we never overflowed.
	require.LessOrEqual(t, c.Len(), 64)
}

func TestCache_ConcurrentClearAndWrite_NoRace(t *testing.T) {
	// Clear() races against Put()/Get(); under -race this test is the
	// proof the internal map swap is safe.
	t.Helper()
	c := NewContentFilterCacheWithClock(ContentFilterCacheConfig{MaxEntries: 32}, newFakeClock().Now)

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			c.Put(strconv.Itoa(i), "v")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_, _ = c.Get(strconv.Itoa(i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			c.Clear()
		}
	}()
	wg.Wait()
}
