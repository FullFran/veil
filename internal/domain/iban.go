package domain

import "regexp"

// ibanPattern matches a compact (no spaces) IBAN candidate: a two-letter
// country code, two check digits, and 10 to 30 more alphanumeric
// characters. It only narrows down candidates; validIBANChecksum does the
// actual mod-97 validation. Matching is intentionally restricted to the
// compact form (no internal spaces), mirroring the reference scanner this
// detector was ported from (HagaHarness's sensitive-scan.mjs).
var ibanPattern = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b`)

// IBANDetector finds IBAN bank account numbers. It validates the real
// mod-97 checksum instead of a bare regex, so it does not fire on strings
// that merely look like an IBAN but carry the wrong check digits.
type IBANDetector struct{}

// NewIBANDetector builds an IBANDetector.
func NewIBANDetector() *IBANDetector { return &IBANDetector{} }

// Name identifies this detector.
func (d *IBANDetector) Name() string { return "iban" }

// Detect scans event.Text for valid IBANs.
func (d *IBANDetector) Detect(event Event) []Finding {
	var findings []Finding
	for _, m := range ibanPattern.FindAllString(event.Text, -1) {
		if !validIBANChecksum(m) {
			continue
		}
		findings = append(findings, Finding{
			Detector: "iban",
			Reason:   "IBAN detected",
			Redacted: m[:4] + "************",
			Match:    m,
			Category: "IBAN",
		})
	}
	return findings
}

// validIBANChecksum validates compact (a two-letter country code, two
// check digits, and the BBAN) against the real mod-97 IBAN checksum: move
// the first four characters to the end, expand every letter into its
// two-digit alphabetic position (A=10 ... Z=35), and confirm the resulting
// decimal number is congruent to 1 modulo 97.
func validIBANChecksum(compact string) bool {
	rearranged := compact[4:] + compact[:4]

	remainder := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			v := int(r-'A') + 10
			remainder = (remainder*10 + v/10) % 97
			remainder = (remainder*10 + v%10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}
