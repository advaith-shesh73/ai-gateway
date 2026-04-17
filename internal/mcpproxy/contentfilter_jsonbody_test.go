// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// TestAppendPIITextBody_MatchesJSONMarshalOnFixtures pins that the
// hand-rolled encoder produces byte-identical output to
// [json.Marshal](map[string]string{"text": s}) for the representative
// cases we know the wire format depends on: ASCII, unicode,
// JSON-special chars, HTML-unsafe chars, control chars, UTF-8
// surrogate-range escapes, and empty string.
func TestAppendPIITextBody_MatchesJSONMarshalOnFixtures(t *testing.T) {
	fixtures := []string{
		"",
		"hello",
		"hello world",
		`"quoted"`,
		`back\slash`,
		"tab\there\nnewline",
		"control\x00null\x01soh",
		"html <script>&amp;</script>",
		"emoji 🔥 unicode",
		"chinese 你好",
		"arabic مرحبا",
		"paragraph\u2029separator",
		"line\u2028separator",
		"all specials: \"\\ \b\f\n\r\t <>&",
		strings.Repeat("a", 4096),
		strings.Repeat("<", 4096),
		// Random-looking chunk with escapes sprinkled in.
		`user said: "hello {\"foo\": \"bar\"}"` + "\n\twith embedded\nnewlines",
	}
	for _, s := range fixtures {
		want, err := json.Marshal(map[string]string{"text": s})
		require.NoError(t, err)
		got := appendPIITextBody(nil, s)
		require.Equal(t, string(want), string(got),
			"fixture %q: hand-rolled encoder must match json.Marshal byte-for-byte", s)
	}
}

// TestAppendPIITextBody_ReusesDstBuffer lets callers pass a
// preallocated buffer to avoid re-allocating on every request. The
// returned slice must include the pre-populated bytes followed by the
// encoded body.
func TestAppendPIITextBody_ReusesDstBuffer(t *testing.T) {
	prefix := []byte("prefix:")
	got := appendPIITextBody(prefix, "hi")
	require.True(t, strings.HasPrefix(string(got), "prefix:"),
		"encoder must not clobber preexisting dst bytes")
	require.Equal(t, `prefix:{"text":"hi"}`, string(got))
}

// TestAppendPIITextBody_SmallDstGrows proves the encoder handles a
// zero-cap dst without corruption (regression check for the initial
// cap-reservation heuristic).
func TestAppendPIITextBody_SmallDstGrows(t *testing.T) {
	want := `{"text":"x"}`
	for _, initCap := range []int{0, 1, 4, 8, 16, 32, 64} {
		got := appendPIITextBody(make([]byte, 0, initCap), "x")
		require.Equal(t, want, string(got), "initial cap=%d", initCap)
	}
}

// FuzzAppendPIITextBody_MatchesJSONMarshal asserts bit-identity for
// arbitrary input strings. Runs as part of the standard corpus-based
// fuzz suite; under `go test -fuzz` it will explore mutation-space
// aggressively.
func FuzzAppendPIITextBody_MatchesJSONMarshal(f *testing.F) {
	seeds := []string{
		"",
		"plain ascii",
		`"quotes" and \backslashes\`,
		"ctrl\x00\x01\x1F",
		"multibyte 🚀 字",
		"\u2028\u2029",
		strings.Repeat("<script>", 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// json.Marshal rejects invalid UTF-8 by replacing with
		// U+FFFD; the hand-rolled path passes invalid bytes
		// through. The invariant holds only for valid UTF-8, which
		// covers the real-world input (log/user text is always
		// valid UTF-8). Skip invalid inputs to keep the fuzz
		// differential sound.
		if !utf8.ValidString(s) {
			t.Skip("invalid UTF-8 out of scope")
		}
		want, err := json.Marshal(map[string]string{"text": s})
		if err != nil {
			t.Skip()
		}
		got := appendPIITextBody(nil, s)
		if !bytes.Equal(got, want) {
			t.Fatalf("byte-level mismatch for %q\n  want %q\n   got %q", s, want, got)
		}
	})
}

// BenchmarkPIIBodyEncode_JSONMarshal is the baseline we are trying to
// beat: the current implementation path.
func BenchmarkPIIBodyEncode_JSONMarshal(b *testing.B) {
	texts := benchTexts()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(map[string]string{"text": texts[i%len(texts)]})
	}
}

// BenchmarkPIIBodyEncode_HandRolled is the new path. Call with
//
//	go test -bench BenchmarkPIIBodyEncode -benchmem ./internal/mcpproxy/
//
// The hand-rolled encoder should be ≥2x faster with fewer allocations
// than the json.Marshal baseline.
func BenchmarkPIIBodyEncode_HandRolled(b *testing.B) {
	texts := benchTexts()
	buf := make([]byte, 0, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = appendPIITextBody(buf[:0], texts[i%len(texts)])
	}
}

// benchTexts is a set of representative PII-service inputs: mix of
// small/medium/large, mostly-ASCII with a sprinkle of escapes.
func benchTexts() []string {
	return []string{
		"short plain text",
		"medium plain text with some words and punctuation, like this.",
		strings.Repeat("log line with some identifiers user=alice id=42 ", 16),
		strings.Repeat("<html>body with </html> tags and ", 8) + "some unicode: 你好",
		`JSON-looking {"nested":"object","arr":[1,2,3]} embedded in text`,
	}
}
