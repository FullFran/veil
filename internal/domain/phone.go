package domain

import (
	"regexp"
)

// phoneWithPrefixPattern matches a Spanish phone number written with its
// country code, as "+34" or "0034", also in parentheses ("(+34)",
// "(0034)"), with or without a single space before the 9-digit number.
var phoneWithPrefixPattern = regexp.MustCompile(`(?:\+34|0034|\(\+34\)|\(0034\))[ ]?[6789][0-9]{8}\b`)

// barePhonePattern matches a bare 9-digit Spanish phone number: mobile
// numbers start with 6 or 7, landlines with 8 or 9.
var barePhonePattern = regexp.MustCompile(`\b[6789][0-9]{8}\b`)

// PhoneDetector finds Spanish phone numbers, either written with a +34
// country code or as a bare 9-digit number.
type PhoneDetector struct{}

// NewPhoneDetector builds a PhoneDetector.
func NewPhoneDetector() *PhoneDetector { return &PhoneDetector{} }

// Name identifies this detector.
func (d *PhoneDetector) Name() string { return "phone" }

// Detect scans event.Text for Spanish phone numbers. It matches the
// prefixed form first so a prefixed number is reported once, as a single
// finding covering the country code; the bare-number pattern then skips
// any match that falls inside a prefixed match already found, so the same
// 9 digits are never reported twice. Every finding is keyed by its E.164
// form (see phoneKey), so one number is one pseudonym however it is
// written.
func (d *PhoneDetector) Detect(event Event) []Finding {
	var findings []Finding

	var prefixed [][]int
	for _, idx := range phoneWithPrefixPattern.FindAllStringIndex(event.Text, -1) {
		// "0034" carries no "+" or "(" to start it, so it must not be the
		// tail of a longer word or digit run ("ref0034…", "10034…").
		if event.Text[idx[0]] == '0' && idx[0] > 0 && isASCIIWord(event.Text[idx[0]-1]) {
			continue
		}
		prefixed = append(prefixed, idx)
		findings = append(findings, phoneFinding(event.Text[idx[0]:idx[1]]))
	}

	for _, idx := range barePhonePattern.FindAllStringIndex(event.Text, -1) {
		if withinAny(idx, prefixed) {
			continue
		}
		findings = append(findings, phoneFinding(event.Text[idx[0]:idx[1]]))
	}

	findings = append(findings, separatedPhoneFindings(event.Text)...)
	return findings
}

func phoneFinding(match string) Finding {
	return Finding{
		Detector: "phone",
		Reason:   "Spanish phone number detected",
		Redacted: "*********",
		Match:    match,
		Category: "TEL",
		Key:      phoneKey(match),
	}
}

// withinAny reports whether idx falls entirely inside one of ranges.
func withinAny(idx []int, ranges [][]int) bool {
	for _, r := range ranges {
		if idx[0] >= r[0] && idx[1] <= r[1] {
			return true
		}
	}
	return false
}
