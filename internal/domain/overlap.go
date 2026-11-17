package domain

import (
	"sort"
	"strings"
)

// withOverlapRuns returns findings plus one synthesized finding for every
// run of partially overlapping matches in the event's text or fields.
// Substitution replaces whole matches, longest first at each position,
// so of "Ana Ruiz" and "Ruiz López" in "Ana Ruiz López" it would replace
// one and leave the rest of the other in clear; the run "Ana Ruiz López"
// is longer than both, so it is replaced as one. A synthesized finding
// takes the category of the longest match in its run (the earliest on a
// tie). A match that only contains or only touches another needs nothing:
// longest-first already covers the first, and the second leaves nothing.
func withOverlapRuns(event Event, findings []Finding) []Finding {
	if len(findings) < 2 {
		return findings
	}
	byMatch := make(map[string]Finding, len(findings))
	for _, f := range findings {
		if f.Match == "" {
			continue
		}
		if _, seen := byMatch[f.Match]; !seen {
			byMatch[f.Match] = f
		}
	}
	if len(byMatch) < 2 {
		return findings
	}
	capable := overlapCapable(byMatch)
	if len(capable) == 0 {
		return findings
	}
	texts := make([]string, 0, 1+len(event.Fields))
	texts = append(texts, event.Text)
	for _, v := range event.Fields {
		texts = append(texts, v)
	}
	out := findings
	for _, text := range texts {
		if !containsAny(text, capable) {
			continue
		}
		for _, run := range overlapRuns(text, byMatch) {
			if _, known := byMatch[run.Match]; known {
				continue
			}
			byMatch[run.Match] = run
			out = append(out, run)
		}
	}
	return out
}

type occurrence struct {
	start, end int
	f          Finding
}

// overlapRuns returns, for text, a finding for each maximal run of match
// occurrences in which every occurrence overlaps the run built so far by
// at least one byte, when the run is longer than each of its members.
func overlapRuns(text string, byMatch map[string]Finding) []Finding {
	var occ []occurrence
	for m, f := range byMatch {
		for from := 0; from < len(text); {
			i := strings.Index(text[from:], m)
			if i < 0 {
				break
			}
			start := from + i
			occ = append(occ, occurrence{start, start + len(m), f})
			from = start + 1
		}
	}
	if len(occ) < 2 {
		return nil
	}
	sort.Slice(occ, func(i, j int) bool {
		if occ[i].start != occ[j].start {
			return occ[i].start < occ[j].start
		}
		return occ[i].end > occ[j].end
	})
	var runs []Finding
	flush := func(start, end int, longest Finding, members int) {
		if members > 1 && end-start > len(longest.Match) {
			run := longest
			run.Match, run.Key = text[start:end], ""
			runs = append(runs, run)
		}
	}
	start, end, longest, members := occ[0].start, occ[0].end, occ[0].f, 1
	for _, o := range occ[1:] {
		if o.start < end {
			if o.end > end {
				end = o.end
			}
			if len(o.f.Match) > len(longest.Match) {
				longest = o.f
			}
			members++
			continue
		}
		flush(start, end, longest, members)
		start, end, longest, members = o.start, o.end, o.f, 1
	}
	flush(start, end, longest, members)
	return runs
}

// overlapCapable returns the matches that can overlap another in part:
// two occurrences overlap in part only when a proper suffix of one is a
// proper prefix of the other. Most finding sets (distinct DNIs, emails)
// have none, and then no text is scanned at all.
func overlapCapable(byMatch map[string]Finding) []string {
	prefixes := make(map[string]bool)
	for m := range byMatch {
		for i := 1; i < len(m); i++ {
			prefixes[m[:i]] = true
		}
	}
	var capable []string
	for m := range byMatch {
		for i := 1; i < len(m); i++ {
			if prefixes[m[i:]] {
				capable = append(capable, m)
				break
			}
		}
	}
	return capable
}

func containsAny(text string, matches []string) bool {
	for _, m := range matches {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}
