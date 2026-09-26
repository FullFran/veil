package domain

import (
	"regexp"
	"strconv"
	"strings"
)

// dniControlLetters is the fixed 23-letter sequence used by the real
// Spanish DNI/NIE control letter algorithm: the letter at index (n mod 23)
// is the correct check letter for number n.
const dniControlLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// dniPattern matches an 8-digit DNI or a NIE (X, Y or Z followed by 7
// digits), followed by one letter, on word boundaries. It only narrows
// down candidates; validDNIControlLetter does the actual validation.
var dniPattern = regexp.MustCompile(`\b([0-9]{8}|[XYZxyz][0-9]{7})([A-Za-z])\b`)

// DNIDetector finds Spanish DNI/NIE national identity numbers. It
// validates the control letter with the real modulo-23 algorithm instead
// of a bare regex, so it does not fire on numbers that merely look like a
// DNI but carry the wrong check letter.
type DNIDetector struct{}

// NewDNIDetector builds a DNIDetector.
func NewDNIDetector() *DNIDetector { return &DNIDetector{} }

// Name identifies this detector.
func (d *DNIDetector) Name() string { return "dni" }

// Detect scans event.Text for valid Spanish DNI/NIE numbers.
func (d *DNIDetector) Detect(event Event) []Finding {
	var findings []Finding
	for _, m := range dniPattern.FindAllStringSubmatch(event.Text, -1) {
		digits := m[1]
		letter := strings.ToUpper(m[2])
		if !validDNIControlLetter(digits, letter) {
			continue
		}
		findings = append(findings, Finding{
			Detector: "dni",
			Reason:   "Spanish DNI/NIE detected",
			Redacted: strings.Repeat("*", len(digits)) + letter,
			Match:    m[0],
			Category: "DNI",
		})
	}
	return findings
}

// validDNIControlLetter validates digits+letter against the real DNI/NIE
// modulo-23 control letter algorithm. digits is either 8 numeric
// characters (a DNI) or an X/Y/Z prefix followed by 7 digits (a NIE);
// letter is a single uppercase character.
func validDNIControlLetter(digits, letter string) bool {
	numberPart := digits

	switch digits[0] {
	case 'X', 'x':
		numberPart = "0" + digits[1:]
	case 'Y', 'y':
		numberPart = "1" + digits[1:]
	case 'Z', 'z':
		numberPart = "2" + digits[1:]
	}

	n, err := strconv.Atoi(numberPart)
	if err != nil {
		return false
	}

	expected := dniControlLetters[n%23]
	return letter[0] == expected
}
