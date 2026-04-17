// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Hand-rolled JSON body encoder for the PII anonymize request (L21).
//
// Shape: {"text":"<escaped user text>"}.
//
// The PII service is on the hot path of every MCP tool call that
// routes through content filtering. [json.Marshal] of a
// map[string]string for each call allocates a map, uses reflection,
// and sorts keys — measurable overhead at 1 kHz. [appendPIITextBody]
// produces byte-identical output to the project's
// [github.com/envoyproxy/ai-gateway/internal/json] Marshal
// (sonic-backed, HTML-unsafe by default) for map[string]string{"text": s},
// with zero reflection and a single preallocated buffer.
//
// Byte-for-byte equality is enforced by
// [FuzzAppendPIITextBody_MatchesJSONMarshal] (see contentfilter_jsonbody_test.go).
// Any change here that breaks the invariant will surface immediately.

// appendPIITextBody appends `{"text":"<escaped s>"}` to dst and
// returns the extended slice. Caller-provided dst lets the hot path
// reuse a per-goroutine buffer and avoid allocation.
//
// Escaping semantics match the project's internal JSON encoder
// (sonic, HTML-unsafe by default):
//   - " and \\ escape to \" and \\\\.
//   - \n, \r, \t use their short form (\n \r \t).
//   - All other control bytes < 0x20 — including \b (0x08) and
//     \f (0x0C), which sonic does NOT short-form — are emitted as
//     \uXXXX.
//   - The HTML-sensitive bytes <, >, & pass through VERBATIM (unlike
//     encoding/json's default).
//   - U+2028 / U+2029 pass through as 3-byte UTF-8 (sonic does not
//     escape them).
func appendPIITextBody(dst []byte, s string) []byte {
	// Preallocate assuming ≤10% of bytes need escaping. This is a
	// bet; the append path handles over- and under-estimates safely.
	if cap(dst)-len(dst) < len(s)+16 {
		grown := make([]byte, len(dst), len(dst)+len(s)+16)
		copy(grown, dst)
		dst = grown
	}
	dst = append(dst, '{', '"', 't', 'e', 'x', 't', '"', ':', '"')
	dst = appendJSONString(dst, s)
	dst = append(dst, '"', '}')
	return dst
}

// hexLower is the lowercase hex alphabet. encoding/json uses
// lowercase for \uXXXX escapes; matching that keeps bytes identical.
const hexLower = "0123456789abcdef"

// appendJSONString writes s JSON-string-escaped into dst. No outer
// quotes. Matches sonic's default (HTML-unsafe) JSON string
// encoding — see the package doc comment.
func appendJSONString(dst []byte, s string) []byte {
	// Track the last index we flushed so long runs of safe bytes
	// get appended in bulk rather than one-at-a-time.
	start := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x80 {
			// Any non-ASCII byte — including the 3-byte UTF-8
			// sequences for U+2028 / U+2029 — passes through
			// verbatim. sonic does not escape these; matching
			// its wire bytes is the whole point of this encoder.
			continue
		}
		if safeASCIIJSON[b] {
			continue
		}
		// Flush [start, i) as a run.
		if start < i {
			dst = append(dst, s[start:i]...)
		}
		switch b {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		default:
			// Any other control byte (0x00-0x1F). Sonic does not
			// shorten 0x08 (\b) or 0x0C (\f) — it emits the full
			// \u0008 / \u000c form. Emit the long form for every
			// control code below 0x20 except \t \n \r above.
			dst = append(dst, '\\', 'u', '0', '0',
				hexLower[b>>4], hexLower[b&0xF])
		}
		start = i + 1
	}
	if start < len(s) {
		dst = append(dst, s[start:]...)
	}
	return dst
}

// safeASCIIJSON is a lookup table marking ASCII bytes that can pass
// through a JSON-escaped string verbatim (no backslash needed). The
// unsafe bytes are: 0x00-0x1F (controls), 0x22 ("), and 0x5C (\).
// HTML-sensitive bytes (<, >, &) pass through — sonic is HTML-unsafe
// by default.
//
// Declared as a package-level var so the compiler hoists the bounds
// check on every indexed access.
var safeASCIIJSON = func() [128]bool {
	var t [128]bool
	for i := 0x20; i < 0x80; i++ {
		t[i] = true
	}
	t['"'] = false
	t['\\'] = false
	return t
}()
