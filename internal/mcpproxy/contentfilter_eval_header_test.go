// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// headers is a tiny helper to keep the tests readable — builds a
// Go-style “map[string][]string“ from variadic (key, value) pairs.
func headers(kv ...string) map[string][]string {
	if len(kv)%2 != 0 {
		panic("headers() requires pairs")
	}
	out := make(map[string][]string, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		out[kv[i]] = append(out[kv[i]], kv[i+1])
	}
	return out
}

// headersMulti lets tests build a header map with multiple values per key.
func headersMulti(name string, vals ...string) map[string][]string {
	return map[string][]string{name: vals}
}

func TestHeaderView_LowercasesKeys(t *testing.T) {
	v := NewHeaderView(headers("X-Eval-Exclude-Ticket-Id", "ENG-1"))
	require.Equal(t, "ENG-1", v.Get("x-eval-exclude-ticket-id"))
	require.Equal(t, "ENG-1", v.Get("X-EVAL-EXCLUDE-TICKET-ID"))
}

func TestHeaderView_ListSingleElementFlattens(t *testing.T) {
	v := NewHeaderView(headersMulti("X-Eval-Exclude-Ticket-Id", "ENG-1"))
	require.Equal(t, "ENG-1", v.Get("x-eval-exclude-ticket-id"))
	require.False(t, v.IsMultiValued("x-eval-exclude-ticket-id"))
}

func TestHeaderView_ListMultiElementJoinsAndTracks(t *testing.T) {
	v := NewHeaderView(headersMulti("Accept", "application/json", "text/plain"))
	require.Equal(t, "application/json,text/plain", v.Get("accept"))
	require.True(t, v.IsMultiValued("Accept"))
}

func TestHeaderView_EmptyListFlattensToEmpty(t *testing.T) {
	v := NewHeaderView(map[string][]string{"X-Weird": {}})
	require.Empty(t, v.Get("x-weird"))
	require.False(t, v.IsMultiValued("x-weird"))
}

func TestHeaderView_EmptyStringValueBecomesEmpty(t *testing.T) {
	v := NewHeaderView(headers("X-Plain", ""))
	require.Empty(t, v.Get("x-plain"))
	require.False(t, v.IsMultiValued("x-plain"))
}

func TestHeaderView_NilInputIsEmptyView(t *testing.T) {
	v := NewHeaderView(nil)
	require.Empty(t, v.Get("anything"))
	require.False(t, v.IsMultiValued("anything"))
}

func TestHeaderView_ListWithEmptyStringsFiltered(t *testing.T) {
	// Go HeaderMap can contain empty strings; they don't count as
	// "multi-valued" because they carry no signal. Parity with
	// test_wire.py::test_list_with_empty_strings_filtered.
	v := NewHeaderView(headersMulti("X-Eval-Exclude-Ticket-Id", "ENG-1", "", ""))
	require.Equal(t, "ENG-1", v.Get("x-eval-exclude-ticket-id"))
	require.False(t, v.IsMultiValued("x-eval-exclude-ticket-id"))
}

func TestHeaderView_MixedStringAndList(t *testing.T) {
	v := NewHeaderView(map[string][]string{
		"X-Eval-Exclude-Ticket-Id": {"ENG-1"},
		"X-Plain":                  {"plain"},
	})
	require.Equal(t, "ENG-1", v.Get("X-Eval-Exclude-Ticket-Id"))
	require.Equal(t, "plain", v.Get("x-plain"))
}

func TestHeaderView_CommaJoinedSingleStringNotTracked(t *testing.T) {
	// A comma-joined single-string value is ambiguous on the wire
	// (nginx will collapse repeated headers). We intentionally do NOT
	// flag it as multi-value because we can't distinguish.
	v := NewHeaderView(headers("X-Eval-Exclude-Ticket-Id", "ENG-1,ENG-2"))
	require.False(t, v.IsMultiValued("x-eval-exclude-ticket-id"))
}

// --- EvalTicketID extraction (parity with test_wire.py) ---

func TestEvalTicketID_BasicExtractionCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "ENG-912818", "ENG-912818"},
		{"trim_whitespace", "  ENG-1  ", "ENG-1"},
		{"empty_value", "", ""},
		{"literal_none_lower", "none", ""},
		{"literal_none_title", "None", ""},
		{"literal_none_upper", "NONE", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewHeaderView(headers("X-Eval-Exclude-Ticket-Id", tc.input))
			got, err := v.EvalTicketID("x-eval-exclude-ticket-id", false)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestEvalTicketID_HeaderMissingReturnsEmpty(t *testing.T) {
	v := NewHeaderView(nil)
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", false)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestEvalTicketID_CommaJoinedTakesFirstNonEmptyNonNone(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"two_values_takes_first", "ENG-1,ENG-2", "ENG-1"},
		{"inner_whitespace_trimmed", " ENG-1 , ENG-2 ", "ENG-1"},
		{"skips_leading_empty", ",ENG-2", "ENG-2"},
		{"skips_none_token", "none,ENG-2", "ENG-2"},
		{"all_none_returns_empty", "none,none", ""},
		{"all_empty_returns_empty", ",,,", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewHeaderView(headers("X-Eval-Exclude-Ticket-Id", tc.raw))
			got, err := v.EvalTicketID("x-eval-exclude-ticket-id", false)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestEvalTicketID_GoStyleMultiValueHeaderTakesFirst(t *testing.T) {
	// When Go delivers the header as a []string with 2+ non-empty
	// entries we flatten to "ENG-1,ENG-2" and non-strict mode falls
	// into the comma-split branch, yielding "ENG-1" (the first token).
	v := NewHeaderView(headersMulti("X-Eval-Exclude-Ticket-Id", "ENG-1", "ENG-2"))
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", false)
	require.NoError(t, err)
	require.Equal(t, "ENG-1", got)
}

// --- Strict mode ---

func TestEvalTicketID_StrictRaisesOnListMultiValue(t *testing.T) {
	v := NewHeaderView(headersMulti("X-Eval-Exclude-Ticket-Id", "ENG-1", "ENG-2"))
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", true)
	require.Empty(t, got)
	var mve *MultiValueEvalHeaderError
	require.ErrorAs(t, err, &mve)
	require.Equal(t, "x-eval-exclude-ticket-id", mve.Header)
}

func TestEvalTicketID_StrictAllowsSingleValue(t *testing.T) {
	v := NewHeaderView(headersMulti("X-Eval-Exclude-Ticket-Id", "ENG-1"))
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", true)
	require.NoError(t, err)
	require.Equal(t, "ENG-1", got)
}

func TestEvalTicketID_StrictDoesNotRaiseOnCommaJoinedString(t *testing.T) {
	// A comma-joined string isn't "multi-valued on the wire" even
	// though it has multiple tokens — we only flag Go-style lists.
	v := NewHeaderView(headers("X-Eval-Exclude-Ticket-Id", "ENG-1,ENG-2"))
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", true)
	require.NoError(t, err)
	require.Equal(t, "ENG-1", got)
}

func TestEvalTicketID_StrictDoesNotRaiseWhenHeaderMissing(t *testing.T) {
	v := NewHeaderView(nil)
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", true)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestEvalTicketID_StrictDoesNotRaiseOnEmptyAndNoneLists(t *testing.T) {
	// A list whose non-empty entries collapse to a single "none" is
	// semantically the same as an absent header — strict must not
	// fire on this case.
	v := NewHeaderView(headersMulti("X-Eval-Exclude-Ticket-Id", "none", "", ""))
	got, err := v.EvalTicketID("x-eval-exclude-ticket-id", true)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestEvalTicketID_MultiValueErrorImplementsError(t *testing.T) {
	// The strict error must plug into errors.As and expose a stable
	// message so it can be caught by a single dispatch-level branch.
	e := &MultiValueEvalHeaderError{Header: "x-foo"}
	require.EqualError(t, e, "ambiguous multi-valued eval header: x-foo")

	var generic error = e
	var asMVE *MultiValueEvalHeaderError
	require.ErrorAs(t, generic, &asMVE)
	require.Equal(t, "x-foo", asMVE.Header)
}

// --- Safety ---

func TestHeaderView_IsReusableAcrossLookups(t *testing.T) {
	// HeaderView is read-only after construction; multiple lookups
	// should return identical results with no side effects.
	v := NewHeaderView(headers("X-Eval", "ENG-42"))
	for i := 0; i < 4; i++ {
		got, err := v.EvalTicketID("x-eval", false)
		require.NoError(t, err)
		require.Equal(t, "ENG-42", got)
		require.Equal(t, "ENG-42", v.Get("X-Eval"))
	}
}

func TestHeaderView_DoesNotMutateInputMap(t *testing.T) {
	input := map[string][]string{
		"X-Eval":  {"ENG-1", "ENG-2"},
		"X-Plain": {"one"},
	}
	_ = NewHeaderView(input)
	require.Equal(t, []string{"ENG-1", "ENG-2"}, input["X-Eval"])
	require.Equal(t, []string{"one"}, input["X-Plain"])
	require.Len(t, input, 2)
}
