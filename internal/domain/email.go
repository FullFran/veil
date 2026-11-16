package domain

import (
	"regexp"
	"unicode"
	"unicode/utf8"
)

// emailPattern matches an ordinary email address. The local part and the
// domain take Unicode letters, marks and digits as well as ASCII: RFC 6531
// (SMTPUTF8) and RFC 6532 extend the address syntax with UTF-8, and IDN
// domains (RFC 5890) are written with their U-labels ("josé@bücher.de").
// It deliberately does not exclude RFC 2606 example domains the way
// HagaHarness's sensitive-scan.mjs does: veil scans live agent traffic,
// not documentation, so a "user@example.com" in a real prompt is still
// worth rewriting rather than silently ignoring.
//
// RE2's \b is ASCII-only, so the word boundaries are checked by hand in
// emailBoundaries.
var emailPattern = regexp.MustCompile(`[\p{L}\p{M}\p{N}._%+-]+@[\p{L}\p{M}\p{N}.-]+\.[\p{L}\p{M}]{2,}`)

// EmailDetector finds email addresses.
type EmailDetector struct{}

// NewEmailDetector builds an EmailDetector.
func NewEmailDetector() *EmailDetector { return &EmailDetector{} }

// Name identifies this detector.
func (d *EmailDetector) Name() string { return "email" }

// Detect scans event.Text for email addresses.
func (d *EmailDetector) Detect(event Event) []Finding {
	var findings []Finding
	for _, idx := range emailPattern.FindAllStringIndex(event.Text, -1) {
		if !emailBoundaries(event.Text, idx[0], idx[1]) {
			continue
		}
		findings = append(findings, Finding{
			Detector: "email",
			Reason:   "email address detected",
			Redacted: "***@***",
			Match:    event.Text[idx[0]:idx[1]],
			Category: "EMAIL",
		})
	}
	return findings
}

// emailBoundaries reports whether the address is not glued to a word
// character on either side ("a@b.es2x" is not an address).
func emailBoundaries(text string, start, end int) bool {
	isWord := func(r rune) bool {
		return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
	}
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); isWord(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); isWord(r) {
			return false
		}
	}
	return true
}
