package domain

import (
	"regexp"
	"strings"
)

// cifPattern matches a Spanish CIF (company tax ID) candidate: an
// organisation-type letter, an optional hyphen, seven digits and a
// control character. The letters are the ones current CIFs use (K, L, M,
// X, Y and Z belong to people's NIF/NIE). It only narrows candidates;
// validCIF does the actual check.
var cifPattern = regexp.MustCompile(`(?i)[A-HJNP-SUVW]-?[0-9]{7}[0-9A-J]`)

// cifControlLetters maps the control value 0-9 to its letter form.
const cifControlLetters = "JABCDEFGHI"

// CIFDetector finds Spanish CIF company tax IDs. It checks the real
// control character, and whether the organisation type takes a digit or
// a letter there, so it does not fire on codes that only look like one.
type CIFDetector struct{}

// NewCIFDetector builds a CIFDetector.
func NewCIFDetector() *CIFDetector { return &CIFDetector{} }

// Name identifies this detector.
func (d *CIFDetector) Name() string { return "cif" }

// Detect scans event.Text for valid CIFs, compact ("B12345674") or with a
// hyphen after the letter ("B-12345674").
func (d *CIFDetector) Detect(event Event) []Finding {
	text := event.Text
	var findings []Finding
	spans := findSeparated(text, cifPattern, func(start, end int) bool {
		return asciiWordBoundaries(text, start, end, "") && validCIF(compactOf(text[start:end]))
	})
	for _, s := range spans {
		match := text[s[0]:s[1]]
		key := compactOf(match)
		f := Finding{
			Detector: "cif",
			Reason:   "Spanish CIF detected",
			Redacted: key[:1] + strings.Repeat("*", 7) + key[8:],
			Match:    match,
			Category: "CIF",
		}
		if key != match {
			f.Key = key
		}
		findings = append(findings, f)
	}
	return findings
}

// validCIF checks a compact uppercase CIF: the control value is ten minus
// the last digit of (the digits in even positions plus the digit sums of
// twice the digits in odd positions). Types N, P, Q, R, S and W carry it
// as a letter, A, B, E and H as a digit, the rest either way.
func validCIF(cif string) bool {
	if len(cif) != 9 {
		return false
	}
	total := 0
	for i := 1; i <= 7; i++ {
		v := int(cif[i] - '0')
		if i%2 == 1 { // odd position within the seven digits
			v *= 2
			v = v/10 + v%10
		}
		total += v
	}
	control := (10 - total%10) % 10
	digit, letter := byte('0'+control), cifControlLetters[control]
	switch c := cif[8]; strings.IndexByte("NPQRSW", cif[0]) >= 0 {
	case true:
		return c == letter
	default:
		if strings.IndexByte("ABEH", cif[0]) >= 0 {
			return c == digit
		}
		return c == digit || c == letter
	}
}
