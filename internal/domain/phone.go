package domain

import "regexp"

// phoneWithPrefixPattern matches a Spanish phone number written with its
// +34 country code, with or without a single space before the 9-digit
// number.
var phoneWithPrefixPattern = regexp.MustCompile(`\+34[ ]?[6789][0-9]{8}\b`)

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

// Detect scans event.Text for Spanish phone numbers. It matches the +34
// form first so a prefixed number is reported once, as a single finding
// covering the country code; the bare-number pattern then skips any match
// that falls inside a +34 match already found, so the same 9 digits are
// never reported twice.
func (d *PhoneDetector) Detect(event Event) []Finding {
	var findings []Finding

	prefixed := phoneWithPrefixPattern.FindAllStringIndex(event.Text, -1)
	for _, idx := range prefixed {
		findings = append(findings, phoneFinding(event.Text[idx[0]:idx[1]]))
	}

	for _, idx := range barePhonePattern.FindAllStringIndex(event.Text, -1) {
		if withinAny(idx, prefixed) {
			continue
		}
		findings = append(findings, phoneFinding(event.Text[idx[0]:idx[1]]))
	}

	return findings
}

func phoneFinding(match string) Finding {
	return Finding{
		Detector: "phone",
		Reason:   "Spanish phone number detected",
		Redacted: "*********",
		Match:    match,
		Category: "TEL",
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
