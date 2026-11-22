package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// diacriticFold maps accented Latin runes commonly found in Spanish names
// to their unaccented base letter, so catalog matching is accent
// insensitive (both "María" and "Maria" match a catalog entry of either
// form).
var diacriticFold = map[rune]rune{
	'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a',
	'é': 'e', 'è': 'e', 'ë': 'e', 'ê': 'e',
	'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i',
	'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o',
	'ú': 'u', 'ù': 'u', 'ü': 'u', 'û': 'u',
	'ñ': 'n',
}

// foldRune lowercases and accent-folds a single rune for catalog matching.
func foldRune(r rune) rune {
	r = toLowerRune(r)
	if folded, ok := diacriticFold[r]; ok {
		return folded
	}
	return r
}

// toLowerRune lowercases ASCII and the accented runes this package cares
// about; it deliberately does not pull in unicode.ToLower's full Unicode
// case-folding table since veil's name catalog only targets Spanish names.
func toLowerRune(r rune) rune {
	switch {
	case r >= 'A' && r <= 'Z':
		return r + ('a' - 'A')
	case r >= 'À' && r <= 'Þ' && r != '×':
		// Latin-1 Supplement uppercase block; lowercase equivalents sit
		// exactly 0x20 later, mirroring ASCII's case offset.
		return r + 0x20
	default:
		return r
	}
}

// foldText returns the case- and accent-folded text for s, plus runeAt:
// for every byte offset of folded (and one past its end), the index of the
// original rune that byte came from. A match found in folded is cut from
// the ORIGINAL rune slice through runeAt, so a rune the fold leaves
// multi-byte ("¿", "€", "«", "ç", emoji) never shifts where a name is cut.
func foldText(s string) (folded string, original []rune, runeAt []int) {
	original = []rune(s)
	var b strings.Builder
	runeAt = make([]int, 0, len(s)+1)
	for i, r := range original {
		before := b.Len()
		b.WriteRune(foldRune(r))
		for range b.Len() - before {
			runeAt = append(runeAt, i)
		}
	}
	runeAt = append(runeAt, len(original))
	return b.String(), original, runeAt
}

// NameCatalogDetector flags whole-word, case- and accent-insensitive
// occurrences of names from a fixed catalog (typically a client's staff
// and customer names).
type NameCatalogDetector struct {
	patterns []*regexp.Regexp
}

// NewNameCatalogDetector builds a NameCatalogDetector matching any of
// names, compared case- and accent-insensitively on whole-word boundaries.
// A name that folds to an empty string (e.g. blank input) is skipped.
func NewNameCatalogDetector(names []string) *NameCatalogDetector {
	patterns := make([]*regexp.Regexp, 0, len(names))
	for _, name := range names {
		folded, _, _ := foldText(name)
		folded = strings.TrimSpace(folded)
		if folded == "" {
			continue
		}
		patterns = append(patterns, regexp.MustCompile(`\b`+regexp.QuoteMeta(folded)+`\b`))
	}
	return &NameCatalogDetector{patterns: patterns}
}

// Name identifies this detector.
func (d *NameCatalogDetector) Name() string { return "name-catalog" }

// Detect scans event.Text for catalog names. Matching is done against a
// folded (lowercased, accent-stripped) copy of the text so that runs
// consistently see "María", "MARIA" and "maria" as the same name, while
// Match always carries the exact original substring so Policy can
// pseudonymize precisely what appeared in the real text.
func (d *NameCatalogDetector) Detect(event Event) []Finding {
	if len(d.patterns) == 0 {
		return nil
	}

	folded, original, runeAt := foldText(event.Text)

	var findings []Finding
	for _, pattern := range d.patterns {
		for _, idx := range pattern.FindAllStringIndex(folded, -1) {
			start, end := extendJoined(original, runeAt[idx[0]], runeAt[idx[1]])
			if afterStreetType(string(original[max(0, start-32):start])) {
				continue // a street named after someone, not the person
			}
			match := string(original[start:end])
			findings = append(findings, Finding{
				Detector: "name-catalog",
				Reason:   "catalog name detected",
				Redacted: "[NOMBRE]",
				Match:    match,
				Category: "NOMBRE",
			})
		}
	}
	return findings
}

// isNameJoiner reports whether r joins two parts of one written name:
// a hyphen ("García-López", also U+2010) or an apostrophe ("O'Neill",
// also U+2019).
func isNameJoiner(r rune) bool {
	return r == '-' || r == '\u2010' || r == '\'' || r == '\u2019'
}

// extendJoined widens the catalog match original[start:end] over every
// joined name part on either side ("Juan García" in "Juan García-López",
// "María Pérez" in "Ana-María Pérez"), so no part of the written name is
// left in clear and the token is keyed by the whole written name: two
// people whose names share a catalog entry never share a token. A joiner
// not followed by a letter ("García - López", "García-2024") is not part
// of the name.
func extendJoined(original []rune, start, end int) (int, int) {
	for end+1 < len(original) && isNameJoiner(original[end]) && unicode.IsLetter(original[end+1]) {
		end++
		for end < len(original) && unicode.IsLetter(original[end]) {
			end++
		}
	}
	for start >= 2 && isNameJoiner(original[start-1]) && unicode.IsLetter(original[start-2]) {
		start--
		for start > 0 && unicode.IsLetter(original[start-1]) {
			start--
		}
	}
	return start, end
}

// LoadNameCatalog reads a name catalog from path: either a JSON array of
// strings, or one name per line (blank lines ignored). It returns an
// error for a missing or unparseable file rather than silently starting
// with an empty catalog, since a client's name catalog is exactly the
// input that must never silently go missing.
func LoadNameCatalog(path string) ([]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator chooses the catalog file (VEIL_CATALOG or the policy); reading it is the purpose
	if err != nil {
		return nil, fmt.Errorf("domain: read name catalog %s: %w", path, err)
	}

	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var names []string
		if err := json.Unmarshal(data, &names); err != nil {
			return nil, fmt.Errorf("domain: parse name catalog %s as JSON: %w", path, err)
		}
		return names, nil
	}

	var names []string
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		names = append(names, line)
	}
	return names, nil
}
