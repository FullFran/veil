package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Lookalike forms: a value written with Unicode compatibility characters
// ("１２３４５６７８Ｚ", "zed＠example.org"), with default-ignorable format
// characters inside it ("1234<U+200B>5678Z"), or with the decimal digits
// of another script reads to a model as the real value, but no detector
// pattern matches it. The registry therefore scans, besides the raw text,
// a lookalike view of it:
//
//   - NFKC (Unicode Standard Annex #15) maps compatibility forms to their
//     canonical characters and composes decomposed accents;
//   - Default_Ignorable_Code_Point characters (UAX #44) are removed;
//   - decimal digits (General_Category Nd) of any script become ASCII.
//
// The view keeps, for every byte, the original bytes it came from, so a
// finding on the view is reported with the original written span as
// Match (what Policy replaces) and the canonical value as Key (what the
// token is minted for and rehydration writes back). UTS #39 confusable
// skeletons are deliberately not used: they are meant only to compare
// strings, and they map digits to letters ("0" to "O").

// lookalikeView is the normalized text plus, for every byte of it, the
// [start, end) of the original bytes that produced it.
type lookalikeView struct {
	text       string
	start, end []int
}

// needsLookalikeView reports whether s has anything the view would
// change. ASCII text and text that is already NFKC with no default
// ignorable and no non-ASCII digit skip the second scan.
func needsLookalikeView(s string) bool {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return false
	}
	if !norm.NFKC.IsNormalString(s) {
		return true
	}
	for _, r := range s {
		if r >= utf8.RuneSelf && (isDefaultIgnorable(r) || unicode.Is(unicode.Nd, r)) {
			return true
		}
	}
	return false
}

// newLookalikeView builds the view of s one normalization segment at a
// time. A segment NFKC leaves unchanged is mapped rune by rune, so a long
// already-normal run never widens a span past the value it holds.
func newLookalikeView(s string) lookalikeView {
	var v lookalikeView
	var b strings.Builder
	b.Grow(len(s))
	emit := func(r rune, start, end int) {
		if isDefaultIgnorable(r) {
			return
		}
		before := b.Len()
		b.WriteRune(foldDigit(r))
		for range b.Len() - before {
			v.start = append(v.start, start)
			v.end = append(v.end, end)
		}
	}
	var it norm.Iter
	it.InitString(norm.NFKC, s)
	for !it.Done() {
		segStart := it.Pos()
		seg := string(it.Next())
		segEnd := it.Pos()
		if seg == s[segStart:segEnd] {
			for i, r := range seg {
				emit(r, segStart+i, segStart+i+utf8.RuneLen(r))
			}
			continue
		}
		for _, r := range seg {
			emit(r, segStart, segEnd)
		}
	}
	v.text = b.String()
	return v
}

// original returns the original bytes of s behind view bytes
// [start, end).
func (v lookalikeView) original(s string, start, end int) string {
	return s[v.start[start]:v.end[end-1]]
}

// isDefaultIgnorable reports the Default_Ignorable_Code_Point property of
// UAX #44: Other_Default_Ignorable_Code_Point + Cf + Variation_Selector,
// minus White_Space, U+FFF9..U+FFFB, U+13430..U+1343F and
// Prepended_Concatenation_Mark (format characters that stay visible).
func isDefaultIgnorable(r rune) bool {
	if r < utf8.RuneSelf {
		return false
	}
	if !unicode.Is(unicode.Cf, r) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) && !unicode.Is(unicode.Variation_Selector, r) {
		return false
	}
	if (r >= 0xFFF9 && r <= 0xFFFB) || (r >= 0x13430 && r <= 0x1343F) {
		return false
	}
	return !unicode.Is(unicode.White_Space, r) && !unicode.Is(unicode.Prepended_Concatenation_Mark, r)
}

// foldDigit maps a decimal digit of any script to its ASCII digit.
// Unicode encodes every Nd digit set as a contiguous run from zero to
// nine, so the value is the offset from the start of the run; Go's Nd
// table keeps those runs whole (TestNdRangesAreWholeDigitRuns).
func foldDigit(r rune) rune {
	if r < utf8.RuneSelf || !unicode.Is(unicode.Nd, r) {
		return r
	}
	const digits = "0123456789"
	c := int(r)
	for _, rg := range unicode.Nd.R16 {
		if lo := int(rg.Lo); c >= lo && c <= int(rg.Hi) {
			return rune(digits[(c-lo)%10])
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if lo := int(rg.Lo); c >= lo && c <= int(rg.Hi) {
			return rune(digits[(c-lo)%10])
		}
	}
	return r
}

// lookalikeFindings runs detect on the lookalike view of event.Text and
// returns its findings that the raw scan did not already report, each
// with Match set to the original written span and Key to the canonical
// value. Fields and Args are not given to the view scan: detectors that
// read them (a secret path) already ran on the raw event, and a view
// finding is only useful when it names a span of Text.
func lookalikeFindings(event Event, raw []Finding, detect func(Event) ([]Finding, error)) ([]Finding, error) {
	if !needsLookalikeView(event.Text) {
		return nil, nil
	}
	view := newLookalikeView(event.Text)
	viewEvent := event
	viewEvent.Text, viewEvent.Fields, viewEvent.Args = view.text, nil, nil

	seen := make(map[string]bool, len(raw))
	for _, f := range raw {
		seen[f.Match] = true
	}
	viewFindings, err := detect(viewEvent)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, f := range viewFindings {
		if f.Match == "" || f.Category == "" {
			continue
		}
		key := f.Key
		if key == "" {
			key = f.Match
		}
		for at := 0; ; {
			i := strings.Index(view.text[at:], f.Match)
			if i < 0 {
				break
			}
			start, end := at+i, at+i+len(f.Match)
			at = end
			written := view.original(event.Text, start, end)
			if seen[written] {
				continue
			}
			seen[written] = true
			g := f
			g.Match, g.Key = written, key
			findings = append(findings, g)
		}
	}
	return findings, nil
}
