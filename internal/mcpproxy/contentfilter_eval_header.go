// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"fmt"
	"strings"
)

// MultiValueEvalHeaderError is returned by HeaderView.EvalTicketID when
// strict mode detects that the eval header arrived with two or more
// non-empty values on the wire. A multi-valued eval header means the
// request origin is ambiguous and — in eval mode — we would rather fail
// loudly than silently pick one of the tokens.
//
// Parity: mirrors app/wire.py:MultiValueEvalHeaderError.
type MultiValueEvalHeaderError struct {
	Header string
}

// Error implements the error interface.
func (e *MultiValueEvalHeaderError) Error() string {
	return fmt.Sprintf("ambiguous multi-valued eval header: %s", e.Header)
}

// HeaderView is the preprocessed view of request headers used by the
// content filter. It flattens Go's canonical “map[string][]string“
// shape into a lower-cased “map[string]string“ (values joined by
// ","), and separately tracks which keys arrived with two or more
// non-empty values so downstream handlers can disambiguate "foo: a,b"
// from "foo: a" + "foo: b".
//
// Construct one per inbound request via NewHeaderView and reuse it
// across dispatch; HeaderView is read-only after construction and safe
// to share across goroutines.
//
// Parity: mirrors the _preprocess + eval_ticket_id logic from
// app/wire.py:FilterRequest. No HTTP envelope is modelled here because
// the Go port runs in-process and receives http.Header directly.
type HeaderView struct {
	// flattened stores every header with a lower-cased key. Non-empty
	// values are joined with ",". Absent/all-empty headers flatten to
	// "" rather than being removed — a present-but-empty header is
	// distinguishable from a missing one at this layer.
	flattened map[string]string
	// multiValueKeys is the set of lower-cased header names whose
	// original []string slice contained two or more non-empty strings.
	// Comma-joined single-string values are *not* tracked because
	// upstream proxies (nginx, Envoy) may collapse repeated headers
	// and we cannot reliably distinguish that from a caller-supplied
	// comma list.
	multiValueKeys map[string]struct{}
}

// NewHeaderView builds a HeaderView from raw Go-style headers.
//
// Nil or empty input yields a view whose EvalTicketID returns "" for
// every query. The input map is not mutated and may be safely reused
// by the caller.
func NewHeaderView(raw map[string][]string) HeaderView {
	view := HeaderView{
		flattened:      make(map[string]string, len(raw)),
		multiValueKeys: make(map[string]struct{}),
	}
	for rawKey, rawVals := range raw {
		key := strings.ToLower(rawKey)
		nonEmpty := make([]string, 0, len(rawVals))
		for _, v := range rawVals {
			if v == "" {
				continue
			}
			nonEmpty = append(nonEmpty, v)
		}
		switch len(nonEmpty) {
		case 0:
			view.flattened[key] = ""
		case 1:
			view.flattened[key] = nonEmpty[0]
		default:
			view.flattened[key] = strings.Join(nonEmpty, ",")
			view.multiValueKeys[key] = struct{}{}
		}
	}
	return view
}

// IsMultiValued reports whether the given header name arrived with two
// or more non-empty values on the wire. Name lookup is case-insensitive.
func (h HeaderView) IsMultiValued(name string) bool {
	_, ok := h.multiValueKeys[strings.ToLower(name)]
	return ok
}

// Get returns the flattened value for the given header name (case-
// insensitive). Missing headers return "".
func (h HeaderView) Get(name string) string {
	return h.flattened[strings.ToLower(name)]
}

// EvalTicketID extracts the eval-mode target ticket from the forwarded
// headers, following the exact semantics of
// app/wire.py:FilterRequest.eval_ticket_id.
//
//   - Absent header, whitespace-only header, or literal "none" (any
//     case) → "" with no error.
//   - Comma-separated value → first non-empty non-"none" token (stripped).
//   - Single token → the value stripped of surrounding whitespace.
//
// In strict mode, a header that arrived as a genuinely multi-valued
// list on the wire (two or more non-empty entries) returns a
// *MultiValueEvalHeaderError so the dispatcher can short-circuit to
// an HTTP-400-equivalent decision. A comma-joined single string is
// NOT treated as multi-valued for this purpose (see rationale above).
//
// strict=false preserves the historical "take the first non-'none'
// token" behaviour, matching the sidecar's default.
func (h HeaderView) EvalTicketID(evalHeader string, strict bool) (string, error) {
	header := strings.ToLower(evalHeader)
	if strict {
		if _, multi := h.multiValueKeys[header]; multi {
			return "", &MultiValueEvalHeaderError{Header: evalHeader}
		}
	}

	raw := strings.TrimSpace(h.flattened[header])
	if raw == "" || strings.EqualFold(raw, "none") {
		return "", nil
	}
	if !strings.Contains(raw, ",") {
		return raw, nil
	}
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		if token != "" && !strings.EqualFold(token, "none") {
			return token, nil
		}
	}
	return "", nil
}
