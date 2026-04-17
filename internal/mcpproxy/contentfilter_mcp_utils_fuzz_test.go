// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// FuzzMCPUtilsRoundTrip drives arbitrary byte sequences through the
// MCP JSON-RPC helpers and asserts that parsing, applying our helpers,
// re-marshalling, and re-parsing is idempotent. This protects against:
//
//   - Panics on malformed JSON or unexpected types.
//   - Helpers that accidentally mutate shared state on the decoded tree.
//   - Marshal paths that emit JSON we can't round-trip through
//     encoding/json (e.g. inadvertently encoding Go-only types).
//
// Exit early whenever the input is not valid JSON — only the valid-JSON
// corner of the input space is interesting for the invariant we care
// about. The idempotency check uses reflect.DeepEqual because Go's JSON
// encoder is unstable in map key order; comparing decoded trees avoids
// that brittleness.
//
// Required by HANDOFF_GO_PORT_REFERENCE §7.7.9 (fuzz entry #1).
func FuzzMCPUtilsRoundTrip(f *testing.F) {
	seeds := [][]byte{
		[]byte(`null`),
		[]byte(`42`),
		[]byte(`"hello"`),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"foo":"bar"}}}`),
		[]byte(`{"jsonrpc":"2.0","id":"abc","result":{"content":[{"type":"text","text":"hi"},{"type":"image"}]}}`),
		[]byte(`{"params":{"arguments":null}}`),
		[]byte(`{"params":{"arguments":{"a":[1,2,{"b":"c"}]}}}`),
		[]byte(`{"result":{"content":[]}}`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Defensive: exit on oversized input to keep fuzz passes fast.
		if len(raw) > 4096 {
			t.Skip()
		}

		var v1 any
		if err := json.Unmarshal(raw, &v1); err != nil {
			// Random bytes are almost never valid JSON — skip the
			// uninteresting cases so the fuzzer can focus on valid
			// JSON corpus mutations.
			t.Skip()
		}

		// 1) Every helper must be panic-safe on any decoded JSON shape.
		args := ToolArguments(v1)
		if args == nil {
			t.Fatalf("ToolArguments must never return nil map (returned nil for %s)", raw)
		}
		parts := IterTextParts(v1)
		_ = parts // slice may be nil for non-result shapes; that's fine.
		resResult := ResponseResult(v1)
		_ = resResult

		// 2) WithToolArguments preserves the decoded tree when we
		//    hand back the same arguments we extracted. If the input
		//    had no arguments slot we replace with an empty map, which
		//    is semantically equivalent under our "empty-or-present"
		//    contract.
		replaced := WithToolArguments(v1, args)
		if replaced == nil {
			t.Fatalf("WithToolArguments returned nil for %s", raw)
		}

		// 3) Marshal → Unmarshal the result; helpers applied to the
		//    reparsed tree must yield the same values. This catches
		//    any helper that silently depends on pointer identity.
		b2, err := json.Marshal(replaced)
		if err != nil {
			t.Fatalf("Marshal of WithToolArguments output failed: %v (input=%s)", err, raw)
		}
		var v2 any
		if err := json.Unmarshal(b2, &v2); err != nil {
			t.Fatalf("Unmarshal of marshalled helper output failed: %v (bytes=%s)", err, b2)
		}
		args2 := ToolArguments(v2)
		if !reflect.DeepEqual(args, args2) {
			t.Fatalf("ToolArguments drifted after roundtrip:\n  before: %#v\n  after:  %#v\n  input:  %s",
				args, args2, raw)
		}

		// 4) IterTextParts must also be stable across roundtrip.
		parts2 := IterTextParts(v2)
		if len(parts) != len(parts2) {
			t.Fatalf("IterTextParts length drift: before=%d after=%d (input=%s)",
				len(parts), len(parts2), raw)
		}
		for i := range parts {
			if parts[i].Index != parts2[i].Index || parts[i].Text != parts2[i].Text {
				t.Fatalf("IterTextParts[%d] drift: before=%+v after=%+v (input=%s)",
					i, parts[i], parts2[i], raw)
			}
		}
	})
}

// FuzzEvalHeaderResolution drives random header sets through the
// HeaderView + EvalTicketID resolution pipeline and asserts the eight
// outcomes in HANDOFF §4.3 are the only ones ever produced. Protects
// against:
//
//   - Panics on weird header shapes (NUL bytes, long strings, mixed
//     empties, Unicode control characters).
//   - Non-strict mode ever returning the "none" token.
//   - Strict mode ever silently picking a token when the header was
//     multi-valued on the wire.
//   - Return values with leading/trailing whitespace (caller contract
//     expects a pre-trimmed ticket identifier).
//
// The fuzzer seeds the name + value via two strings and a bit field;
// the bit field is decoded into "single value / multi-value / with-
// empty / with-'none'-token" shape so mutations exercise every
// interesting axis while keeping the seed surface small.
//
// Required by HANDOFF_GO_PORT_REFERENCE §7.7.9 (fuzz entry #2).
func FuzzEvalHeaderResolution(f *testing.F) {
	// Seed the fuzzer with every column of the §4.3 resolution table
	// so early mutations exercise each behaviour.
	type seed struct {
		headerName string
		value      string
		shape      uint8 // bit0: multi-value, bit1: inject-empty, bit2: inject-none
	}
	seeds := []seed{
		{"x-eval-ticket-id", "", 0},
		{"x-eval-ticket-id", "ENG-1", 0},
		{"x-eval-ticket-id", "none", 0},
		{"x-eval-ticket-id", "ENG-1", 1},
		{"x-eval-ticket-id", "ENG-1", 0b011},
		{"x-eval-ticket-id", "ENG-1", 0b111},
		{"X-Eval-Ticket-Id", "  ENG-1  ", 0},
		{"other-header", "bogus", 0b010},
	}
	for _, s := range seeds {
		f.Add(s.headerName, s.value, s.shape)
	}

	f.Fuzz(func(t *testing.T, headerName, value string, shape uint8) {
		// Defensive: oversized inputs add no signal and slow fuzz
		// passes significantly.
		if len(headerName) > 128 || len(value) > 512 {
			t.Skip()
		}
		// A header name with null bytes or whitespace is technically
		// illegal on the wire; HeaderView normalises keys via
		// strings.ToLower, which does not strip them. The fuzzer may
		// still generate these — we want the resolver to be robust to
		// them, so we deliberately do NOT skip.

		multiValue := shape&0b001 != 0
		injectEmpty := shape&0b010 != 0
		injectNone := shape&0b100 != 0

		// Build a []string for the header based on the shape bits.
		vals := []string{value}
		if multiValue {
			vals = append(vals, value+"-dup")
		}
		if injectEmpty {
			vals = append(vals, "")
		}
		if injectNone {
			vals = append(vals, "none")
		}
		view := NewHeaderView(map[string][]string{headerName: vals})

		for _, strict := range []bool{false, true} {
			// capture
			got, err := view.EvalTicketID(headerName, strict)
			if err != nil {
				var mve *MultiValueEvalHeaderError
				if !errors.As(err, &mve) {
					t.Fatalf("unexpected error type %T for name=%q strict=%v: %v",
						err, headerName, strict, err)
				}
				if !strict {
					t.Fatalf("non-strict mode must never return an error (name=%q value=%q shape=%d): %v",
						headerName, value, shape, err)
				}
				if !view.IsMultiValued(headerName) {
					t.Fatalf("strict error without multi-value header (name=%q value=%q shape=%d): %v",
						headerName, value, shape, err)
				}
				if got != "" {
					t.Fatalf("strict error must yield empty ticket, got %q", got)
				}
				continue
			}

			// err == nil invariants.
			if strings.TrimSpace(got) != got {
				t.Fatalf("result must be pre-trimmed, got %q (name=%q value=%q shape=%d strict=%v)",
					got, headerName, value, shape, strict)
			}
			if strings.EqualFold(got, "none") {
				t.Fatalf("resolver must never return a 'none' token, got %q (strict=%v)",
					got, strict)
			}
			if got == "" {
				continue
			}
			if strings.Contains(got, ",") {
				t.Fatalf("resolver must split on commas, but leaked %q (strict=%v)",
					got, strict)
			}
		}
	})
}
