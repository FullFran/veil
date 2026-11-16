package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
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
			match := string(original[runeAt[idx[0]]:runeAt[idx[1]]])
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

// LoadNameCatalog reads a name catalog from path: either a JSON array of
// strings, or one name per line (blank lines ignored). It returns an
// error for a missing or unparseable file rather than silently starting
// with an empty catalog, since a client's name catalog is exactly the
// input that must never silently go missing.
func LoadNameCatalog(path string) ([]string, error) {
	data, err := os.ReadFile(path)
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
