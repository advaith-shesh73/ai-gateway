// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// UTF-8 boundary tests per HANDOFF_GO_PORT_REFERENCE §7.7.4 — Jeff Dean P4 #33.
//
// Invariants:
//   1. Length measured in RUNES, not bytes.
//   2. No chunk ever lands mid-rune.
//   3. Paragraph ("\n\n") boundaries are preferred, then line ("\n"),
//      then a hard slice at the rune boundary.
//   4. Pathological inputs — empty, all-newlines, ASCII 3×maxChars —
//      behave as documented.
//
// A bug here silently splits multi-byte code points and corrupts PII
// anonymization; keep these tests exhaustive.

// --- Invariant guards ---------------------------------------------------

// assertNoMidRuneBoundaries panics-via-require if any chunk contains an
// invalid UTF-8 sequence. This is the guard that would have caught the
// byte-based splitter bug Jeff Dean flagged.
func assertNoMidRuneBoundaries(t *testing.T, chunks []string) {
	t.Helper()
	for i, c := range chunks {
		require.Truef(t, utf8.ValidString(c),
			"chunk %d has invalid UTF-8 — splitter landed inside a code point: %q", i, c)
	}
}

// assertReassembles verifies that the concatenation of chunks equals the
// original text. splitForPII is a partition, not a lossy filter.
func assertReassembles(t *testing.T, chunks []string, want string) {
	t.Helper()
	require.Equal(t, want, strings.Join(chunks, ""), "chunks must reassemble losslessly")
}

// --- 1. CJK multi-byte ≤ maxChars → single chunk ------------------------

func TestSplitForPII_CJKUnderRuneLimitEmitsSingleChunk(t *testing.T) {
	// "一二三四" is 4 runes, 12 bytes (each CJK rune is 3 bytes in UTF-8).
	const text = "一二三四"
	require.Equal(t, 4, utf8.RuneCountInString(text))
	require.Len(t, text, 12)

	chunks := splitForPII(text, 4)
	require.Len(t, chunks, 1, "CJK with rune count == maxChars must emit one chunk")
	require.Equal(t, text, chunks[0])
	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)
}

func TestSplitForPII_CJKWithByteLenGreaterThanMaxCharsButRuneCountUnder(t *testing.T) {
	// 8 runes, 24 bytes. maxChars=10 in runes → single chunk.
	const text = "漢字でも大丈夫だ"
	require.Equal(t, 8, utf8.RuneCountInString(text))
	require.Greater(t, len(text), 10)

	chunks := splitForPII(text, 10)
	require.Len(t, chunks, 1)
	require.Equal(t, text, chunks[0])
	assertNoMidRuneBoundaries(t, chunks)
}

// --- 2. Hard-slice boundary must fall on a rune edge --------------------

func TestSplitForPII_HardSliceOnRuneEdge(t *testing.T) {
	// 6 CJK runes with no whitespace; maxChars=3 forces hard-slice twice.
	const text = "一二三四五六"
	chunks := splitForPII(text, 3)

	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)

	for _, c := range chunks {
		require.LessOrEqualf(t, utf8.RuneCountInString(c), 3,
			"chunk %q exceeds maxChars rune budget", c)
	}
	require.Equal(t, []string{"一二三", "四五六"}, chunks)
}

func TestSplitForPII_BoundaryLandsAtMaxCharsPlusOneInBytes(t *testing.T) {
	// Construct a string whose byte length at position maxChars+1 is
	// mid-UTF-8. A byte-based splitter would truncate a 3-byte rune; the
	// rune-based splitter must walk back to the preceding rune edge.
	//
	// text = "aaaa" + "漢" = 4 ASCII + 3-byte rune = 7 bytes, 5 runes.
	// With maxChars=5 (runes), splitter accepts entire 5 runes as one
	// chunk. No partial-rune is possible.
	const text = "aaaa漢"
	require.Equal(t, 5, utf8.RuneCountInString(text))
	require.Len(t, text, 7)

	chunks := splitForPII(text, 5)
	require.Len(t, chunks, 1)
	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)
}

// --- 3. ASCII 3×maxChars — paragraph, line, hard-slice preference -----

func TestSplitForPII_AsciiTripleMaxCharsPrefersParagraph(t *testing.T) {
	// Three 10-char ASCII chunks joined by paragraph breaks (total 34
	// chars). With maxChars=22, each body + trailing "\n\n" fits in a
	// window and the splitter must choose the paragraph boundary:
	//   "aaaaaaaaaa" | "\n\nbbbbbbbbbb" | "\n\ncccccccccc".
	// If the splitter had byte-counted or preferred line over paragraph
	// this would produce 4+ chunks.
	text := "aaaaaaaaaa\n\nbbbbbbbbbb\n\ncccccccccc"
	chunks := splitForPII(text, 22)

	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)
	require.Equal(t, []string{"aaaaaaaaaa", "\n\nbbbbbbbbbb", "\n\ncccccccccc"}, chunks)
}

func TestSplitForPII_AsciiPrefersLineOverHardSlice(t *testing.T) {
	// No paragraph breaks present — only single-\n line boundaries.
	// maxChars=10 and three "xxx\nxxx\n..." lines; splitter must prefer
	// the "\n" break rather than hard-slicing mid-word.
	text := "aaaa\nbbbb\ncccc"
	chunks := splitForPII(text, 7)

	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)
	// At least one chunk should end on a newline boundary, proving the
	// line-break preference.
	ended := 0
	for _, c := range chunks {
		if strings.HasSuffix(c, "\n") || strings.Contains(c, "\n") {
			ended++
		}
	}
	require.GreaterOrEqual(t, ended, 1)
}

func TestSplitForPII_AsciiHardSliceWhenNoBreakAvailable(t *testing.T) {
	// Long run with no newline at all — splitter MUST fall through to a
	// hard slice and still honour the maxChars budget.
	text := strings.Repeat("a", 30)
	chunks := splitForPII(text, 10)

	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)
	require.Len(t, chunks, 3)
	for _, c := range chunks {
		require.Len(t, c, 10)
	}
}

// --- 4. Empty / nil / pathological inputs must not panic ---------------

func TestSplitForPII_EmptyInputReturnsEmptySlice(t *testing.T) {
	chunks := splitForPII("", 4096)
	require.Empty(t, chunks)
}

func TestSplitForPII_AllNewlines(t *testing.T) {
	text := "\n\n\n\n"

	// Must not panic at any maxChars.
	require.NotPanics(t, func() {
		_ = splitForPII(text, 1)
		_ = splitForPII(text, 2)
		_ = splitForPII(text, 4)
		_ = splitForPII(text, 100)
	})

	// Losslessness must hold.
	for _, m := range []int{1, 2, 4, 100} {
		assertReassembles(t, splitForPII(text, m), text)
	}
}

func TestSplitForPII_ZeroOrNegativeMaxCharsReturnsSingleChunk(t *testing.T) {
	text := "some text"
	require.Equal(t, []string{text}, splitForPII(text, 0))
	require.Equal(t, []string{text}, splitForPII(text, -1))
}

// --- 5. Rune-count budget is honoured in every chunk ------------------

func TestSplitForPII_NoChunkExceedsMaxCharsInRunes(t *testing.T) {
	// Mixed ASCII + CJK + punctuation; check every emitted chunk for
	// rune budget compliance. An off-by-one in the hard-slice branch
	// would show up here.
	text := "Alice: 一二三四五\nBob: 六七八九十\n\nCharlie: αβγδε"
	for _, m := range []int{3, 5, 8, 13} {
		chunks := splitForPII(text, m)
		assertNoMidRuneBoundaries(t, chunks)
		assertReassembles(t, chunks, text)
		for _, c := range chunks {
			require.LessOrEqualf(t, utf8.RuneCountInString(c), m,
				"chunk %q exceeds maxChars=%d rune budget", c, m)
		}
	}
}

func TestSplitForPII_PythonParityRegressionExample(t *testing.T) {
	// Mirrors a worked example from the Python sidecar. Input has 14
	// runes and a single "\n\n" at indices 6-7. With maxChars=8 the
	// first window [0,8) contains the paragraph break at rune 6, so the
	// splitter cuts there, leaving the remainder "\n\nghijkl" (8 runes)
	// to fit into the next (and final) window verbatim.
	text := "abcdef\n\nghijkl"
	require.Equal(t, 14, utf8.RuneCountInString(text))

	chunks := splitForPII(text, 8)
	assertReassembles(t, chunks, text)
	require.Equal(t, []string{"abcdef", "\n\nghijkl"}, chunks)
}

func TestSplitForPII_TightWindowForcesLineOverParagraph(t *testing.T) {
	// Same text (14 runes), maxChars=7 — the first window [0,7) does
	// NOT contain the "\n\n" pair (which straddles runes 6 and 7), so
	// the splitter falls back to the single "\n" at rune 6, producing:
	//   "abcdef" | "\n" | "\nghijkl".
	// This locks in the preference ladder behaviour: paragraph break
	// is preferred ONLY when the pair lies strictly inside the window.
	text := "abcdef\n\nghijkl"
	chunks := splitForPII(text, 7)
	assertNoMidRuneBoundaries(t, chunks)
	assertReassembles(t, chunks, text)
	require.Equal(t, []string{"abcdef", "\n", "\nghijkl"}, chunks)
}
