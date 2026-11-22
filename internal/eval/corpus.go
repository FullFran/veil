// Package eval measures veil's detectors against an annotated corpus:
// precision and recall per label, span-level micro-F1 under the MEDDOCAN
// convention (a predicted span counts only when its unit, start offset,
// end offset and label all match a gold span exactly) and evaluation
// latency per event.
package eval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/FullFran/veil/internal/domain"
)

// Labels are the span labels the corpus annotates: veil's pseudonym
// categories.
var Labels = []string{"DNI", "IBAN", "EMAIL", "TEL", "NOMBRE", "CIF", "TARJETA", "NSS", "DIRECCION"}

func knownLabel(label string) bool {
	for _, l := range Labels {
		if l == label {
			return true
		}
	}
	return false
}

// ErrMarkup marks a malformed [[LABEL:value]] annotation.
var ErrMarkup = errors.New("eval: malformed annotation")

// Span is one labelled stretch of a unit, in code point offsets (End is
// exclusive), as brat and MEDDOCAN count them.
type Span struct {
	// Unit is the tool-argument field path the span is in ("" for a
	// prompt's text).
	Unit  string
	Start int
	End   int
	Label string
}

// Case is one corpus record, ready to evaluate.
type Case struct {
	ID    string
	Tags  []string
	Event domain.Event
	// Units maps each scanned unit (a field path, or "" for prompt text)
	// to its plain text.
	Units map[string]string
	Gold  []Span
}

// Corpus is a loaded corpus directory.
type Corpus struct {
	Dir         string
	CatalogPath string
	Cases       []Case
}

type record struct {
	ID   string         `json:"id"`
	Tags []string       `json:"tags"`
	Text *string        `json:"text"`
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
}

// ParseMarkup strips [[LABEL:value]] annotations from s and returns the
// plain text and the gold spans, tagged with unit.
func ParseMarkup(s, unit string) (string, []Span, error) {
	var plain strings.Builder
	var spans []Span
	runes := 0
	for {
		open := strings.Index(s, "[[")
		if open < 0 {
			break
		}
		plain.WriteString(s[:open])
		runes += utf8.RuneCountInString(s[:open])
		rest := s[open+2:]
		closeIdx := strings.Index(rest, "]]")
		if closeIdx < 0 {
			return "", nil, fmt.Errorf("%w: unclosed annotation", ErrMarkup)
		}
		label, value, ok := strings.Cut(rest[:closeIdx], ":")
		if !ok || value == "" || !knownLabel(label) {
			return "", nil, fmt.Errorf("%w: %q", ErrMarkup, rest[:closeIdx])
		}
		n := utf8.RuneCountInString(value)
		spans = append(spans, Span{Unit: unit, Start: runes, End: runes + n, Label: label})
		plain.WriteString(value)
		runes += n
		s = rest[closeIdx+2:]
	}
	plain.WriteString(s)
	return plain.String(), spans, nil
}

// stripArgs replaces every annotated string leaf of v with its plain
// text, collecting gold spans under the leaf's field path (the same path
// domain.FlattenArgs gives it).
func stripArgs(v any, path string, spans *[]Span) (any, error) {
	switch x := v.(type) {
	case string:
		plain, s, err := ParseMarkup(x, path)
		if err != nil {
			return nil, err
		}
		*spans = append(*spans, s...)
		return plain, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			child, err := stripArgs(e, joinPath(path, escapeKey(k)), spans)
			if err != nil {
				return nil, err
			}
			out[k] = child
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			child, err := stripArgs(e, joinPath(path, fmt.Sprint(i)), spans)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	default:
		return v, nil
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func escapeKey(key string) string {
	return strings.NewReplacer(`\`, `\\`, ".", `\.`).Replace(key)
}

// LoadCorpus reads dir/corpus.jsonl and dir/catalog.json.
func LoadCorpus(dir string) (*Corpus, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "corpus.jsonl")) // #nosec G304 -- corpus directory chosen by the developer running veil-eval
	if err != nil {
		return nil, err
	}
	c := &Corpus{Dir: dir, CatalogPath: filepath.Join(dir, "catalog.json")}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var r record
		if err := domain.DecodeJSON(scanner.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("corpus.jsonl:%d: %w", line, err)
		}
		if r.ID == "" || seen[r.ID] {
			return nil, fmt.Errorf("corpus.jsonl:%d: missing or duplicate id %q", line, r.ID)
		}
		seen[r.ID] = true
		cs, err := buildCase(r)
		if err != nil {
			return nil, fmt.Errorf("corpus.jsonl:%d (%s): %w", line, r.ID, err)
		}
		c.Cases = append(c.Cases, cs)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func buildCase(r record) (Case, error) {
	cs := Case{ID: r.ID, Tags: r.Tags}
	switch {
	case r.Text != nil && r.Args == nil:
		plain, spans, err := ParseMarkup(*r.Text, "")
		if err != nil {
			return Case{}, err
		}
		cs.Event = domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostOpenCode, SessionID: r.ID, Text: plain}
		cs.Units = map[string]string{"": plain}
		cs.Gold = spans
	case r.Args != nil && r.Text == nil:
		var spans []Span
		stripped, err := stripArgs(r.Args, "", &spans)
		if err != nil {
			return Case{}, err
		}
		args := stripped.(map[string]any)
		fields, text := domain.FlattenArgs(args)
		tool := r.Tool
		if tool == "" {
			tool = "bash"
		}
		cs.Event = domain.Event{Kind: domain.EventToolArgs, Host: domain.HostOpenCode, SessionID: r.ID, ToolName: tool, Text: text, Fields: fields, Args: args}
		cs.Units = fields
		cs.Gold = spans
	default:
		return Case{}, errors.New("a record has exactly one of text or args")
	}
	return cs, nil
}

// LoadBaseline reads a committed baseline file.
func LoadBaseline(path string) (Baseline, error) {
	var b Baseline
	raw, err := os.ReadFile(path) // #nosec G304 -- baseline file chosen by the developer running veil-eval
	if err != nil {
		return b, err
	}
	// Unknown fields are an error, so a baseline written for another
	// format (such as the former absolute latencyP95BudgetMicros) fails
	// loudly instead of silently dropping its latency gate.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Baseline{}, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}
