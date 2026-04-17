// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- parity with test_pii_scan.py --------------------------------------

func TestScanTextParts_ReturnsIndexNewTextForChangedParts(t *testing.T) {
	anon := func(_ context.Context, s string) (string, error) {
		return strings.ToUpper(s), nil
	}
	parts := []TextPartInput{{Index: 0, Text: "alpha"}, {Index: 3, Text: "beta"}}
	got, err := ScanTextParts(context.Background(), parts, anon, 2, nil)
	if err != nil {
		t.Fatalf("ScanTextParts err: %v", err)
	}
	want := map[int]string{0: "ALPHA", 3: "BETA"}
	if !mapsEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestScanTextParts_OmitsPartsWhoseTextIsUnchanged(t *testing.T) {
	anon := func(_ context.Context, s string) (string, error) { return s, nil }
	parts := []TextPartInput{{Index: 0, Text: "hello"}, {Index: 1, Text: "world"}}
	got, err := ScanTextParts(context.Background(), parts, anon, 2, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty replacements, got %v", got)
	}
}

func TestScanTextParts_MixedChangedAndUnchanged(t *testing.T) {
	anon := func(_ context.Context, s string) (string, error) {
		if s == "sensitive" {
			return "<X>", nil
		}
		return s, nil
	}
	parts := []TextPartInput{
		{Index: 1, Text: "ok"},
		{Index: 2, Text: "sensitive"},
		{Index: 3, Text: "ok"},
	}
	got, err := ScanTextParts(context.Background(), parts, anon, 2, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := map[int]string{2: "<X>"}
	if !mapsEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestScanTextParts_EmptyInputReturnsEmpty(t *testing.T) {
	anon := func(_ context.Context, _ string) (string, error) {
		t.Fatal("anonymize must not run on empty input")
		return "", nil
	}
	got, err := ScanTextParts(context.Background(), nil, anon, 4, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestScanTextParts_BoundedBySemaphore(t *testing.T) {
	var cur, peak int32
	anon := func(_ context.Context, s string) (string, error) {
		c := atomic.AddInt32(&cur, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if c <= p || atomic.CompareAndSwapInt32(&peak, p, c) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		return s + "_x", nil
	}
	parts := make([]TextPartInput, 10)
	for i := range parts {
		parts[i] = TextPartInput{Index: i, Text: "t" + string(rune('0'+i))}
	}
	if _, err := ScanTextParts(context.Background(), parts, anon, 3, nil); err != nil {
		t.Fatalf("err: %v", err)
	}
	p := atomic.LoadInt32(&peak)
	if p > 3 {
		t.Fatalf("peak > 3: %d", p)
	}
	if p < 2 {
		t.Fatalf("expected parallelism (peak >= 2), got %d", p)
	}
}

func TestScanTextParts_SequentialWhenMaxParallelIsOne(t *testing.T) {
	var order []int
	var mu sync.Mutex
	anon := func(_ context.Context, s string) (string, error) {
		idx := int(s[0] - '0')
		mu.Lock()
		order = append(order, idx)
		mu.Unlock()
		time.Sleep(time.Millisecond)
		mu.Lock()
		order = append(order, -idx)
		mu.Unlock()
		return "<" + s + ">", nil
	}
	parts := make([]TextPartInput, 5)
	for i := range parts {
		parts[i] = TextPartInput{Index: i, Text: string(rune('0' + i))}
	}
	if _, err := ScanTextParts(context.Background(), parts, anon, 1, nil); err != nil {
		t.Fatalf("err: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < len(order); i += 2 {
		if order[i] != -order[i+1] {
			t.Fatalf("overlapping execution with sem=1 at idx %d: %v", i, order)
		}
	}
}

func TestScanTextParts_ZeroMaxIsClampedToOne(t *testing.T) {
	var calls atomic.Int32
	anon := func(_ context.Context, s string) (string, error) {
		calls.Add(1)
		return s + "!", nil
	}
	parts := []TextPartInput{{Index: 0, Text: "a"}, {Index: 1, Text: "b"}}
	got, err := ScanTextParts(context.Background(), parts, anon, 0, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := map[int]string{0: "a!", 1: "b!"}
	if !mapsEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("expected 2 anonymize calls, got %d", n)
	}
}

func TestScanTextParts_ExceptionPropagatesAndCancelsSiblings(t *testing.T) {
	anon := func(ctx context.Context, s string) (string, error) {
		if s == "boom" {
			return "", errors.New("pii service exploded")
		}
		// Other parts block briefly; if we did NOT cancel siblings
		// they'd finish before the error propagates and the error
		// message might race a successful return. This assertion only
		// cares that the error is surfaced.
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
		return s + "_ok", nil
	}
	parts := []TextPartInput{
		{Index: 0, Text: "ok"},
		{Index: 1, Text: "boom"},
		{Index: 2, Text: "also ok"},
	}
	_, err := ScanTextParts(context.Background(), parts, anon, 3, nil)
	if err == nil {
		t.Fatalf("expected error to propagate")
	}
	if !strings.Contains(err.Error(), "pii service exploded") && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- preprocessor parity ------------------------------------------------

func TestScanTextParts_PreprocessorRunsBeforeAnonymize(t *testing.T) {
	var captured []string
	var mu sync.Mutex
	anon := func(_ context.Context, s string) (string, error) {
		mu.Lock()
		captured = append(captured, s)
		mu.Unlock()
		return s, nil
	}
	preprocess := SubstringScrubber("ENG-123", "<TICKET>")
	parts := []TextPartInput{{Index: 0, Text: "see ENG-123 for details"}}
	if _, err := ScanTextParts(context.Background(), parts, anon, 1, preprocess); err != nil {
		t.Fatalf("err: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 1 || captured[0] != "see <TICKET> for details" {
		t.Fatalf("preprocess not applied: %#v", captured)
	}
}

func TestScanTextParts_PreprocessorChangeAloneCountsAsReplacement(t *testing.T) {
	anon := func(_ context.Context, s string) (string, error) { return s, nil }
	preprocess := SubstringScrubber("secret", "<R>")
	parts := []TextPartInput{{Index: 7, Text: "a secret value"}}
	got, err := ScanTextParts(context.Background(), parts, anon, 1, preprocess)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := map[int]string{7: "a <R> value"}
	if !mapsEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestScanTextParts_NonePreprocessorIsIdentity(t *testing.T) {
	anon := func(_ context.Context, s string) (string, error) {
		return strings.ToUpper(s), nil
	}
	parts := []TextPartInput{{Index: 0, Text: "hi"}}
	got, err := ScanTextParts(context.Background(), parts, anon, 1, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := map[int]string{0: "HI"}
	if !mapsEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

// ---- SubstringScrubber parity -------------------------------------------

func TestSubstringScrubber_EmptyNeedleReturnsIdentity(t *testing.T) {
	s := SubstringScrubber("", "<X>")
	if got := s("anything at all"); got != "anything at all" {
		t.Fatalf("identity broken: %q", got)
	}
}

func TestSubstringScrubber_ReplacesLiteralSubstring(t *testing.T) {
	s := SubstringScrubber("ENG-123", "<TICKET>")
	if got := s("see ENG-123 again"); got != "see <TICKET> again" {
		t.Fatalf("got %q", got)
	}
}

func TestSubstringScrubber_ReplacesMultipleOccurrences(t *testing.T) {
	s := SubstringScrubber("secret", "<R>")
	if got := s("secret\nsecret\nsecret"); got != "<R>\n<R>\n<R>" {
		t.Fatalf("got %q", got)
	}
}

func TestSubstringScrubber_NoMatchReturnsInputUnchanged(t *testing.T) {
	s := SubstringScrubber("ENG-999", "<TICKET>")
	if got := s("see ENG-123"); got != "see ENG-123" {
		t.Fatalf("got %q", got)
	}
}

func TestSubstringScrubber_CaseSensitiveByDefault(t *testing.T) {
	s := SubstringScrubber("secret", "<R>")
	if got := s("SECRET lives"); got != "SECRET lives" {
		t.Fatalf("got %q", got)
	}
}

func mapsEqual(a, b map[int]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
