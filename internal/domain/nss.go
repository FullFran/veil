package domain

import (
	"regexp"
	"strconv"
	"strings"
)

// nssPattern matches a Spanish social security number (NSS) candidate:
// two province digits, eight digits and two control digits, together or
// separated by one kind of space, slash or hyphen ("28/12345678/40").
var nssPattern = regexp.MustCompile(`[0-9]{2}[ /-]?[0-9]{8}[ /-]?[0-9]{2}`)

// NSSDetector finds Spanish social security numbers. It checks the
// province code and the real mod-97 control digits.
type NSSDetector struct{}

// NewNSSDetector builds an NSSDetector.
func NewNSSDetector() *NSSDetector { return &NSSDetector{} }

// Name identifies this detector.
func (d *NSSDetector) Name() string { return "nss" }

// Detect scans event.Text for valid NSS numbers.
func (d *NSSDetector) Detect(event Event) []Finding {
	text := event.Text
	var findings []Finding
	spans := findSeparated(text, nssPattern, func(start, end int) bool {
		return standaloneDigitGroups(text, start, end) && validNSS(text[start:end])
	})
	for _, s := range spans {
		match := text[s[0]:s[1]]
		key := nssCompact(match)
		f := Finding{
			Detector: "nss",
			Reason:   "Spanish social security number detected",
			Redacted: strings.Repeat("*", 10) + key[10:],
			Match:    match,
			Category: "NSS",
		}
		if key != match {
			f.Key = key
		}
		findings = append(findings, f)
	}
	return findings
}

func nssCompact(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '/' || r == '-' {
			return -1
		}
		return r
	}, s)
}

// validNSS checks a written candidate: both separators the same (or
// none), a province code 01 to 53, and control digits equal to the number
// mod 97, where a number under ten million counts as province*10^7 +
// number and any other as province followed by number.
func validNSS(written string) bool {
	if len(written) == 14 && written[2] != written[11] {
		return false
	}
	if len(written) == 13 { // one separator only: mixed form, reject
		return false
	}
	key := nssCompact(written)
	if len(key) != 12 {
		return false
	}
	province, _ := strconv.Atoi(key[:2])
	number, _ := strconv.Atoi(key[2:10])
	control, _ := strconv.Atoi(key[10:])
	if province < 1 || province > 53 {
		return false
	}
	var base int
	if number < 10_000_000 {
		base = province*10_000_000 + number
	} else {
		base, _ = strconv.Atoi(key[:10])
	}
	return base%97 == control
}
