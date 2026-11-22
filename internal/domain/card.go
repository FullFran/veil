package domain

import (
	"regexp"
	"strings"
)

// cardPattern matches a payment card number candidate: 13 to 19 digits
// together, or written in groups ("4111 1111 1111 1111", Amex's
// "3782 822463 10005") separated by one kind of space or hyphen. The
// issuer prefix and the Luhn check decide; the pattern only narrows.
var cardPattern = regexp.MustCompile(`[0-9]{13,19}|[0-9]{4}(?:[ -][0-9]{3,6}){2,4}`)

// CardDetector finds payment card numbers (PAN). A number must carry a
// known issuer prefix, 13 to 19 digits and a valid Luhn check digit, and
// must stand alone: four groups inside a longer run of groups (an IBAN
// body, a list of codes) are not a card.
type CardDetector struct{}

// NewCardDetector builds a CardDetector.
func NewCardDetector() *CardDetector { return &CardDetector{} }

// Name identifies this detector.
func (d *CardDetector) Name() string { return "card" }

// Detect scans event.Text for valid payment card numbers.
func (d *CardDetector) Detect(event Event) []Finding {
	text := event.Text
	var findings []Finding
	spans := findSeparated(text, cardPattern, func(start, end int) bool {
		return standaloneDigitGroups(text, start, end) && validCard(text[start:end])
	})
	for _, s := range spans {
		match := text[s[0]:s[1]]
		key := compactOf(match)
		f := Finding{
			Detector: "card",
			Reason:   "payment card number detected",
			Redacted: strings.Repeat("*", len(key)-4) + key[len(key)-4:],
			Match:    match,
			Category: "TARJETA",
		}
		if key != match {
			f.Key = key
		}
		findings = append(findings, f)
	}
	return findings
}

// standaloneDigitGroups reports whether text[start:end] is not glued to a
// word character, a decimal point or comma before it, and, when it is
// written in groups, not part of a longer run of separated digit groups
// on either side. A compact number next to another number ("B12345674
// 4111111111111111") is two values, so only grouped forms get that check.
func standaloneDigitGroups(text string, start, end int) bool {
	if !asciiWordBoundaries(text, start, end, ".,") {
		return false
	}
	if !strings.ContainsAny(text[start:end], " -/") {
		return true
	}
	if start >= 2 && strings.IndexByte(" -/", text[start-1]) >= 0 && isDigit(text[start-2]) {
		return false
	}
	return end+1 >= len(text) || strings.IndexByte(" -/", text[end]) < 0 || !isDigit(text[end+1])
}

// validCard checks a written candidate: one kind of separator at most,
// 13 to 19 digits, a known issuer prefix and the Luhn check.
func validCard(written string) bool {
	if strings.Contains(written, " ") && strings.Contains(written, "-") {
		return false
	}
	pan := compactOf(written)
	if len(pan) < 13 || len(pan) > 19 || !knownCardIssuer(pan) {
		return false
	}
	return luhnValid(pan)
}

// knownCardIssuer reports whether pan starts with an issuer prefix of a
// major card network: Visa 4; Mastercard 51-55 and 2221-2720; Maestro,
// Discover and UnionPay 5 and 6; Amex 34 and 37; Diners 30, 36, 38, 39;
// JCB 35.
func knownCardIssuer(pan string) bool {
	switch pan[0] {
	case '4', '5', '6':
		return true
	case '3':
		return strings.IndexByte("045679", pan[1]) >= 0
	case '2':
		p := pan[:4]
		return p >= "2221" && p <= "2720"
	}
	return false
}

// luhnValid runs the Luhn (mod 10) check over a string of ASCII digits.
func luhnValid(digits string) bool {
	sum := 0
	for i := 0; i < len(digits); i++ {
		v := int(digits[len(digits)-1-i] - '0')
		if i%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}
