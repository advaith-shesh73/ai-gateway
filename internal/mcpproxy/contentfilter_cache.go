// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// LRU cache port — parity reference is
// panacea-agent/services/aigw-content-filter/app/reliability.py (LRUCache).
//
// Divergence from the Python port:
//   - Python relies on single-asyncio serialization. Go's PII fan-out
//     exercises the cache from many goroutines concurrently (chunks within
//     a text part are anonymized in parallel — §4.10), so every access
//     MUST hold a mutex. The mutex is the reason this port uses
//     container/list directly instead of an ordered-map library: we want
//     one tight critical section per operation.
//   - The hash construction (SHA-256 of `context + "\x00" + text`) and
//     the hex digest form are kept bit-identical so two nodes running the
//     same policy produce the same cache keys (useful for offline analysis).
//
// L08 — the cache is sharded across [defaultCacheShards] independent
// LRU shards so contention scales with the working-set hot spot, not
// with raw traffic. Sharding is keyed by an FNV-1a hash of the cache
// key. Each shard carries its own mutex, linked list, and map; the
// outer [ContentFilterCache] is a thin fan-out that selects the
// shard. The old single-mutex semantics are recoverable by setting
// [ContentFilterCacheConfig.Shards] to 1.
//
// L09 — optional byte budget. When [ContentFilterCacheConfig.MaxBytes]
// is positive the cache also evicts until each shard's estimated
// in-memory footprint falls below its share. The byte count is an
// approximation (key + value bytes + fixed per-entry overhead), not a
// hard allocation cap, but it prevents a handful of pathological
// large values from dominating the cache memory envelope.

// defaultCacheShards is the default number of shards when
// [ContentFilterCacheConfig.Shards] is not specified. 16 is a small
// enough prime power to keep overhead minimal while being large
// enough to reduce contention meaningfully across typical 8-32
// goroutine pools.
const defaultCacheShards = 16

// perEntryOverheadBytes approximates the fixed overhead of one cache
// entry: the [cacheEntry] struct (key pointer + value pointer +
// [time.Time]), one linked-list element (two pointers + value
// pointer), and one map slot. Tuned conservatively so MaxBytes
// slightly over-accounts; callers that care about exact memory
// should measure.
const perEntryOverheadBytes = 128

// ContentFilterCacheConfig tunables — match Python LRUCache constructor.
//
// MaxEntries bounds memory; TTL bounds staleness. Both defaults agree with
// the Python defaults (1024 entries, 15 min TTL).
//
// Shards (L08) controls the number of independent cache shards. When
// 0 or 1, the cache behaves as a single-shard LRU (backwards-compatible
// semantics). When > 1, keys fan out across shards by FNV-1a hash, and
// the global MaxEntries/MaxBytes budgets are divided evenly.
//
// MaxBytes (L09) bounds the approximate in-memory footprint. 0
// disables the byte budget.
type ContentFilterCacheConfig struct {
	MaxEntries int
	TTL        time.Duration
	Shards     int
	MaxBytes   int64
}

func (c ContentFilterCacheConfig) withDefaults() ContentFilterCacheConfig {
	if c.MaxEntries <= 0 {
		c.MaxEntries = 1024
	}
	if c.TTL <= 0 {
		c.TTL = 15 * time.Minute
	}
	if c.Shards <= 0 {
		c.Shards = defaultCacheShards
	}
	// MaxBytes == 0 is "disabled" — preserve verbatim.
	if c.MaxBytes < 0 {
		c.MaxBytes = 0
	}
	return c
}

// perShardEntries computes the per-shard entry cap via ceiling
// division, clamped to a minimum of 1 so no shard is a black hole.
func (c ContentFilterCacheConfig) perShardEntries() int {
	if c.Shards <= 1 {
		return c.MaxEntries
	}
	n := (c.MaxEntries + c.Shards - 1) / c.Shards
	if n < 1 {
		n = 1
	}
	return n
}

// perShardBytes computes the per-shard byte cap. Returns 0 when the
// cache byte budget is disabled.
func (c ContentFilterCacheConfig) perShardBytes() int64 {
	if c.MaxBytes <= 0 {
		return 0
	}
	if c.Shards <= 1 {
		return c.MaxBytes
	}
	n := c.MaxBytes / int64(c.Shards)
	if n < 1 {
		n = 1
	}
	return n
}

// cacheEntry is the value held in the linked list element.
type cacheEntry struct {
	key      string
	value    string
	storedAt time.Time
}

// approxSize returns the entry's approximate in-memory footprint.
func (e *cacheEntry) approxSize() int64 {
	return int64(len(e.key)+len(e.value)) + perEntryOverheadBytes
}

// cacheShard is one independently-locked LRU partition.
type cacheShard struct {
	mu       sync.Mutex
	order    *list.List               // front = most recent, back = oldest
	items    map[string]*list.Element // key → element holding *cacheEntry
	bytes    int64                    // approx in-memory bytes under mu
	maxEntry int
	maxBytes int64 // 0 disables
	ttl      time.Duration
	nowFn    func() time.Time
}

func newCacheShard(maxEntries int, maxBytes int64, ttl time.Duration, nowFn func() time.Time) *cacheShard {
	return &cacheShard{
		order:    list.New(),
		items:    make(map[string]*list.Element),
		maxEntry: maxEntries,
		maxBytes: maxBytes,
		ttl:      ttl,
		nowFn:    nowFn,
	}
}

func (s *cacheShard) get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	elem, ok := s.items[key]
	if !ok {
		return "", false
	}
	ent := elem.Value.(*cacheEntry)
	if s.nowFn().Sub(ent.storedAt) > s.ttl {
		s.order.Remove(elem)
		delete(s.items, key)
		s.bytes -= ent.approxSize()
		return "", false
	}
	s.order.MoveToFront(elem)
	return ent.value, true
}

func (s *cacheShard) put(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	if elem, ok := s.items[key]; ok {
		ent := elem.Value.(*cacheEntry)
		s.bytes -= ent.approxSize()
		ent.value = value
		ent.storedAt = now
		s.bytes += ent.approxSize()
		s.order.MoveToFront(elem)
		s.evictLocked()
		return
	}
	ent := &cacheEntry{key: key, value: value, storedAt: now}
	elem := s.order.PushFront(ent)
	s.items[key] = elem
	s.bytes += ent.approxSize()
	s.evictLocked()
}

// evictLocked drops entries from the tail until BOTH the entry cap
// AND the byte budget are honored. Caller must hold s.mu.
func (s *cacheShard) evictLocked() {
	for s.order.Len() > s.maxEntry ||
		(s.maxBytes > 0 && s.bytes > s.maxBytes) {
		oldest := s.order.Back()
		if oldest == nil {
			return
		}
		old := oldest.Value.(*cacheEntry)
		s.order.Remove(oldest)
		delete(s.items, old.key)
		s.bytes -= old.approxSize()
	}
}

func (s *cacheShard) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order.Init()
	s.items = make(map[string]*list.Element)
	s.bytes = 0
}

func (s *cacheShard) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

func (s *cacheShard) byteSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// ContentFilterCache is a TTL-aware sharded LRU keyed by the
// content-hash of `context + text`. Safe for concurrent use from many
// goroutines.
type ContentFilterCache struct {
	cfg    ContentFilterCacheConfig
	clock  func() time.Time
	shards []*cacheShard
}

// NewContentFilterCache returns a cache with production defaults and a
// [time.Now] clock. Tests should use [NewContentFilterCacheWithClock].
func NewContentFilterCache(cfg ContentFilterCacheConfig) *ContentFilterCache {
	return newContentFilterCache(cfg, time.Now)
}

// NewContentFilterCacheWithClock is the test-only constructor.
func NewContentFilterCacheWithClock(cfg ContentFilterCacheConfig, clock func() time.Time) *ContentFilterCache {
	return newContentFilterCache(cfg, clock)
}

func newContentFilterCache(cfg ContentFilterCacheConfig, clock func() time.Time) *ContentFilterCache {
	if clock == nil {
		clock = time.Now
	}
	cfg = cfg.withDefaults()
	c := &ContentFilterCache{
		cfg:    cfg,
		clock:  clock,
		shards: make([]*cacheShard, cfg.Shards),
	}
	perEnt := cfg.perShardEntries()
	perByt := cfg.perShardBytes()
	for i := range c.shards {
		c.shards[i] = newCacheShard(perEnt, perByt, cfg.TTL, clock)
	}
	return c
}

// shardFor selects the cache shard for a key using FNV-1a 64. The
// computation is inlined to avoid the []byte allocation and
// hash.Hash interface overhead that [hash/fnv] incurs.
func (c *ContentFilterCache) shardFor(key string) *cacheShard {
	if len(c.shards) == 1 {
		return c.shards[0]
	}
	const (
		fnvOffset64 = 14695981039346656037
		fnvPrime64  = 1099511628211
	)
	h := uint64(fnvOffset64)
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= fnvPrime64
	}
	return c.shards[h%uint64(len(c.shards))]
}

// ContentFilterCacheKey derives the cache key for (context, text). It is a
// bit-for-bit port of the Python `LRUCache.key_for` static method:
//
//	h = sha256()
//	h.update(context.encode("utf-8"))
//	h.update(b"\x00")
//	h.update(text.encode("utf-8"))
//	return h.hexdigest()
//
// `context` participates so two backends that send identical text but
// different policy hints don't share a cache row.
//
// NOTE: for new code that cares about tenant/route isolation, prefer
// [BuildPIIContext] to construct a route-aware context string before
// calling this function, or call [ContentFilterCacheKeyTenant] directly.
// The plain context form survives for backwards compatibility with the
// Python-parity test vectors.
func ContentFilterCacheKey(context, text string) string {
	h := sha256.New()
	h.Write([]byte(context))
	h.Write([]byte{0x00})
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// ContentFilterCacheKeyTenant hashes (context, route, backend, text) with
// explicit \x00 separators and a domain-separator prefix byte (0x01).
// The prefix byte is outside the ASCII range for any legitimate context
// string so the tenant form is provably distinct from the plain
// [ContentFilterCacheKey] form: a caller who migrates from one to the
// other gets a new set of cache rows instead of a silent collision on
// a cleverly-constructed context that happens to contain extra \x00
// bytes.
//
// Use this when the caller already knows the route + backend it belongs
// to; it guarantees two different routes serving the same backend never
// share a cache row even if an operator forgets to namespace the context
// string. Empty route or backend are permitted (they produce a row
// isolated under that empty label — still safely unique).
func ContentFilterCacheKeyTenant(context, route, backend, text string) string {
	h := sha256.New()
	// Domain separator: distinguishes this form from the plain
	// ContentFilterCacheKey so there is no possibility of collision
	// across the two key spaces, regardless of caller-controlled
	// input.
	h.Write([]byte{0x01})
	h.Write([]byte(context))
	h.Write([]byte{0x00})
	h.Write([]byte(route))
	h.Write([]byte{0x00})
	h.Write([]byte(backend))
	h.Write([]byte{0x00})
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// BuildPIIContext returns a canonical PII-context string that folds the
// route, backend, tool, and scope into one namespace. This is the
// string callers pass to [PIIClient.Anonymize]; it becomes both a
// metric label and (via the cache-key hash) a cache partition.
//
// Format is `scope|route|backend|tool`; empty fields render as empty
// segments. The format is public API in the sense that it shows up in
// logs and metrics, so operators can grep for `scope=Response` or
// `route=supportgpt-main` and get a consistent hit.
func BuildPIIContext(scope Scope, route, backend, tool string) string {
	return string(scope) + "|" + route + "|" + backend + "|" + tool
}

// Get returns (value, true) on hit or ("", false) on miss or TTL expiry.
// Expired entries are evicted as a side effect of Get — this matches the
// Python semantics and keeps the hit-rate metric honest.
func (c *ContentFilterCache) Get(key string) (string, bool) {
	return c.shardFor(key).get(key)
}

// Put inserts or updates an entry. Updates promote the key to MRU. When
// the cache is full the oldest entry is evicted.
func (c *ContentFilterCache) Put(key, value string) {
	c.shardFor(key).put(key, value)
}

// Clear evicts every entry. Shards are cleared in order; an in-flight
// Get/Put on a later shard will see that shard's pre-clear state
// until it acquires that shard's mutex — this is fine because a
// concurrent Clear has no cross-shard ordering contract.
func (c *ContentFilterCache) Clear() {
	for _, s := range c.shards {
		s.clear()
	}
}

// Len reports the current number of entries summed across shards.
// Each shard is locked briefly in turn; the returned value is a
// best-effort snapshot, not a consistent cross-shard view.
func (c *ContentFilterCache) Len() int {
	n := 0
	for _, s := range c.shards {
		n += s.len()
	}
	return n
}

// ApproxBytes reports the current approximate in-memory bytes summed
// across shards. Useful for dashboards and the
// `mcp_filter_cache_bytes` gauge.
func (c *ContentFilterCache) ApproxBytes() int64 {
	var n int64
	for _, s := range c.shards {
		n += s.byteSize()
	}
	return n
}

// Shards reports the configured shard count. Stable for the cache's
// lifetime.
func (c *ContentFilterCache) Shards() int { return len(c.shards) }
