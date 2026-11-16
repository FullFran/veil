package domain

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Separated forms: an IBAN, DNI/NIE or Spanish phone written with spaces,
// dots or dashes ("ES91 2100 0418 …", "12.345.678-Z", "600 12 34 56").
// Only strict shapes match, an IBAN or DNI/NIE only with a valid checksum,
// and never as part of something longer (a date, an amount, an invoice
// number, a run of digit groups, a value next to a currency). The shapes
// and boundaries are ported from HagaHarness's pre-veil normaliser
// (core/privacy/separators.mjs), which this replaces.
//
// RE2 has no lookaround, so each pattern only narrows candidates and the
// boundary checks run by hand on the full text. A rejected candidate
// retries one byte later, as a regex lookbehind would.

var (
	ibanSeparatedPattern  = regexp.MustCompile(`(?i)ES[0-9]{2}(?:[ .-]?[0-9]{4}){5}`)
	dniSeparatedPattern   = regexp.MustCompile(`[0-9]{2}\.[0-9]{3}\.[0-9]{3}[ .-]?[A-Za-z]|[0-9]{2} [0-9]{3} [0-9]{3}[ .-]?[A-Za-z]|[0-9]{8}[ .-]?[A-Za-z]`)
	nieSeparatedPattern   = regexp.MustCompile(`[XYZxyz][ .-]?[0-9]{7}[ .-]?[A-Za-z]`)
	phoneSeparatedPattern = regexp.MustCompile(
		`(?:(\+34|0034)[ -]?)?[6789][0-9]{2}(?: [0-9]{3} [0-9]{3}|-[0-9]{3}-[0-9]{3}| [0-9]{2} [0-9]{2} [0-9]{2}|-[0-9]{2}-[0-9]{2}-[0-9]{2})`)
)

// currencies are checked longest first, so "euros" is not read as "eur"
// followed by a letter.
var currencies = []string{"euros", "euro", "eur", "usd", "€", "$"}

// findSeparated returns the [start, end) spans of pattern in text that
// accept() keeps, retrying one byte after every rejected candidate.
func findSeparated(text string, pattern *regexp.Regexp, accept func(start, end int) bool) [][2]int {
	var spans [][2]int
	for pos := 0; pos < len(text); {
		loc := pattern.FindStringIndex(text[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if accept(start, end) {
			spans = append(spans, [2]int{start, end})
			pos = end
			continue
		}
		pos = start + 1
	}
	return spans
}

func isASCIIWord(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func hasSeparator(s string) bool { return strings.ContainsAny(s, " .-") }

func compactOf(s string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '.' || r == '-' {
			return -1
		}
		return r
	}, s))
}

// asciiWordBoundaries reports whether the span is not glued to an ASCII
// word character (nor, when extraBefore is set, to one of those bytes).
func asciiWordBoundaries(text string, start, end int, extraBefore string) bool {
	if start > 0 && (isASCIIWord(text[start-1]) || strings.IndexByte(extraBefore, text[start-1]) >= 0) {
		return false
	}
	return end >= len(text) || !isASCIIWord(text[end])
}

func separatedIBANFindings(text string) []Finding {
	var findings []Finding
	spans := findSeparated(text, ibanSeparatedPattern, func(start, end int) bool {
		return asciiWordBoundaries(text, start, end, "")
	})
	for _, s := range spans {
		match := text[s[0]:s[1]]
		key := compactOf(match)
		if match == key || !validIBANChecksum(key) {
			continue // the compact uppercase form is the IBAN detector's own
		}
		findings = append(findings, Finding{Detector: "iban", Reason: "IBAN detected", Redacted: key[:4] + "************", Match: match, Category: "IBAN", Key: key})
	}
	return findings
}

func separatedDNIFindings(text string) []Finding {
	var findings []Finding
	for _, pattern := range []*regexp.Regexp{dniSeparatedPattern, nieSeparatedPattern} {
		spans := findSeparated(text, pattern, func(start, end int) bool {
			return asciiWordBoundaries(text, start, end, ".,")
		})
		for _, s := range spans {
			match := text[s[0]:s[1]]
			if !hasSeparator(match) {
				continue // the compact form is the DNI detector's own
			}
			key := compactOf(match)
			digits, letter := key[:len(key)-1], key[len(key)-1:]
			if !validDNIControlLetter(digits, letter) {
				continue
			}
			findings = append(findings, Finding{Detector: "dni", Reason: "Spanish DNI/NIE detected", Redacted: strings.Repeat("*", len(digits)) + letter, Match: match, Category: "DNI", Key: key})
		}
	}
	return findings
}

func separatedPhoneFindings(text string) []Finding {
	var findings []Finding
	spans := findSeparated(text, phoneSeparatedPattern, func(start, end int) bool {
		return phoneBefore(text[:start]) && phoneAfter(text[end:])
	})
	for _, s := range spans {
		match := text[s[0]:s[1]]
		body, prefix := match, ""
		if strings.HasPrefix(body, "+34") || strings.HasPrefix(body, "0034") {
			prefix = "+34"
			body = strings.TrimPrefix(strings.TrimPrefix(body, "+34"), "0034")
		}
		key := prefix + strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, body)
		findings = append(findings, phoneFinding(match))
		findings[len(findings)-1].Key = key
	}
	return findings
}

// phoneBefore: not glued to a letter, digit, "_" or "+"; not the tail of a
// digit group ("1.600 …", "2 600 …"); not after a currency ("$ 600 …").
func phoneBefore(before string) bool {
	if before == "" {
		return true
	}
	last, size := utf8.DecodeLastRuneInString(before)
	if unicode.IsLetter(last) || unicode.IsDigit(last) || last == '_' || last == '+' {
		return false
	}
	if n := len(before); n >= 2 && isDigit(before[n-2]) && strings.IndexByte(".,- ", before[n-1]) >= 0 {
		return false
	}
	trimmed := before
	if unicode.IsSpace(last) {
		trimmed = before[:len(before)-size]
	}
	lower := strings.ToLower(trimmed)
	for _, c := range currencies {
		if strings.HasSuffix(lower, c) {
			return false
		}
	}
	return true
}

// phoneAfter: not glued to a letter, digit or "_"; not followed by a
// decimal (",5") or another digit group (" 789", "-789"); not before a
// currency ("… €", "… euros", but "… europa" is fine).
func phoneAfter(after string) bool {
	if after == "" {
		return true
	}
	first, size := utf8.DecodeRuneInString(after)
	if unicode.IsLetter(first) || unicode.IsDigit(first) || first == '_' {
		return false
	}
	if len(after) >= 2 && strings.IndexByte(".,- ", after[0]) >= 0 && isDigit(after[1]) {
		return false
	}
	rest := after
	if unicode.IsSpace(first) {
		rest = after[size:]
	}
	lower := strings.ToLower(rest)
	for _, c := range currencies {
		if strings.HasPrefix(lower, c) {
			if tail := lower[len(c):]; tail == "" || !(tail[0] >= 'a' && tail[0] <= 'z') {
				return false
			}
		}
	}
	return true
}
