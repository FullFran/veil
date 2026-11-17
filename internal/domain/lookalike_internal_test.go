package domain

import (
	"testing"
	"unicode"
)

// foldDigit relies on every range of Go's Nd table being whole digit runs
// (stride 1, a multiple of ten long), so the offset from the start of a
// range modulo ten is the digit value.
func TestNdRangesAreWholeDigitRuns(t *testing.T) {
	for _, rg := range unicode.Nd.R16 {
		if rg.Stride != 1 || (rg.Hi-rg.Lo+1)%10 != 0 {
			t.Errorf("Nd range %U..%U stride %d is not whole digit runs", rg.Lo, rg.Hi, rg.Stride)
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if rg.Stride != 1 || (rg.Hi-rg.Lo+1)%10 != 0 {
			t.Errorf("Nd range %U..%U stride %d is not whole digit runs", rg.Lo, rg.Hi, rg.Stride)
		}
	}
}

func TestFoldDigit(t *testing.T) {
	cases := map[rune]rune{'7': '7', 'a': 'a', '\u0667': '7', '\u096f': '9', '\u0e50': '0', '\U0001d7d7': '9'}
	for in, want := range cases {
		if got := foldDigit(in); got != want {
			t.Errorf("foldDigit(%U) = %U, want %U", in, got, want)
		}
	}
}

func TestIsDefaultIgnorable(t *testing.T) {
	ignorable := []rune{'\u00ad', '\u180e', '\u200b', '\u200c', '\u200d', '\u2060', '\u2066', '\ufe0f', '\ufeff', '\U000e0001'}
	for _, r := range ignorable {
		if !isDefaultIgnorable(r) {
			t.Errorf("isDefaultIgnorable(%U) = false, want true", r)
		}
	}
	// Prepended concatenation marks and interlinear annotation characters
	// are format characters that stay visible; spaces and letters are not
	// format characters at all.
	visible := []rune{' ', 'a', '\u00a0', '\u0600', '\u06dd', '\ufff9', '\U00013430'}
	for _, r := range visible {
		if isDefaultIgnorable(r) {
			t.Errorf("isDefaultIgnorable(%U) = true, want false", r)
		}
	}
}

func TestNewLookalikeView_KeepsVisibleFormatMark(t *testing.T) {
	v := newLookalikeView("a\u0600b\u200bc")
	if v.text != "a\u0600bc" {
		t.Fatalf("view = %q, want the prepended concatenation mark kept and U+200B removed", v.text)
	}
}

func TestNeedsLookalikeView(t *testing.T) {
	cases := map[string]bool{"plain ascii": false, "María Pérez": false, "1234\u200b5678Z": true, "１": true, "\u0661": true, "e\u0301": true}
	for in, want := range cases {
		if got := needsLookalikeView(in); got != want {
			t.Errorf("needsLookalikeView(%q) = %v, want %v", in, got, want)
		}
	}
}
