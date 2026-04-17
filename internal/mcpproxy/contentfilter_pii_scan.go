// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"strings"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// TextPreprocessor is a synchronous transform applied to each text part
// before the PII service sees it. Typical use: literal substring
// scrubbing (e.g. stripping a ticket ID so the GPU model never sees it).
//
// Parity: mirrors `app/pii_scan.py:TextPreprocessor`.
type TextPreprocessor func(text string) string

// TextPartInput is an indexed text part fed into ScanTextParts. The
// index is the caller-defined position within a JSON-RPC response's
// `result.content` array (or equivalent). Preserving indices lets the
// handler splice redactions back in without reordering.
type TextPartInput struct {
	Index int
	Text  string
}

// AnonymizeFn is the narrow interface ScanTextParts needs from a
// PIIClient: given a single text, return the anonymized form or an
// error. It exists so tests can inject a stub without constructing a
// full PIIClient + http.Server.
type AnonymizeFn func(ctx context.Context, text string) (string, error)

// ScanTextParts scrubs each part of `parts` via `anonymize` and returns
// a sparse map of index → replacement. Only indices whose replacement
// differs from the original are included; the caller can skip the
// splice if the map is empty.
//
// Concurrency:
//
//   - Parts are scrubbed in parallel, bounded by maxParallelParts
//     (clamped to >=1 so a misconfigured 0 never silently disables
//     redaction, which would be a PII leak).
//   - Exceptions propagate. The first error cancels the shared context,
//     so sibling chunks bail out rather than continue; partial
//     redaction is worse than no redaction because the caller cannot
//     distinguish which parts were actually scrubbed.
//   - Input order is preserved via index keys; the order in which the
//     semaphore releases does not affect correctness.
//
// Parity: mirrors `app/pii_scan.py:scan_text_parts`. Key Go/Python
// difference: Python uses `asyncio.Semaphore` + `asyncio.gather`, Go
// uses `semaphore.Weighted` + `errgroup`. Both preserve order and both
// propagate the first error.
func ScanTextParts(
	ctx context.Context,
	parts []TextPartInput,
	anonymize AnonymizeFn,
	maxParallelParts int,
	preprocess TextPreprocessor,
) (map[int]string, error) {
	if len(parts) == 0 {
		return map[int]string{}, nil
	}
	if maxParallelParts < 1 {
		maxParallelParts = 1
	}

	sem := semaphore.NewWeighted(int64(maxParallelParts))
	g, gctx := errgroup.WithContext(ctx)

	// Pre-size to avoid resizing under contention. Each goroutine
	// writes to its own index; no map locking required because we use
	// a pre-allocated slice of (text, changed) pairs and build the
	// return map once g.Wait() returns.
	type slot struct {
		text    string
		changed bool
	}
	out := make([]slot, len(parts))

	for i, p := range parts {
		g.Go(func() error {
			return safeGo("pii part worker", func() error {
				if err := sem.Acquire(gctx, 1); err != nil {
					return err
				}
				defer sem.Release(1)

				pre := p.Text
				if preprocess != nil {
					pre = preprocess(p.Text)
				}
				scrubbed, err := anonymize(gctx, pre)
				if err != nil {
					return err
				}
				if scrubbed != p.Text {
					out[i] = slot{text: scrubbed, changed: true}
				}
				return nil
			})
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	result := make(map[int]string, len(parts))
	for i, s := range out {
		if s.changed {
			result[parts[i].Index] = s.text
		}
	}
	return result, nil
}

// SubstringScrubber builds a preprocessor that replaces every
// occurrence of `needle` with `replacement`. Returns the identity
// transform when needle is empty — this lets call sites pass
// `SubstringScrubber(ticket, REDACT_TAG)` unconditionally and still
// skip work on the non-eval path.
//
// Parity: mirrors `app/pii_scan.py:substring_scrubber`. The Python
// implementation uses `str.replace`; Go uses `strings.ReplaceAll`
// which has the same semantics.
func SubstringScrubber(needle, replacement string) TextPreprocessor {
	if needle == "" {
		return func(text string) string { return text }
	}
	return func(text string) string {
		return strings.ReplaceAll(text, needle, replacement)
	}
}
