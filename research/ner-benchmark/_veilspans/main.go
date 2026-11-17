// Command veilspans prints the spans veil's detectors find in research
// cases, so the Python harness can score veil and "veil + model" with the
// same strict-span rule as internal/eval. It lives in a directory whose
// name starts with "_" so that "go build ./...", "go vet ./..." and
// "go test ./..." ignore it: it is research tooling, not part of veil.
//
// Input (stdin, JSONL): {"id": "...", "text": "plain text"} or
// {"id": "...", "tool": "bash", "args": {...plain args...}}.
// Output (stdout, JSONL): {"id": "...", "spans": [{"unit","start","end","label"}]}.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/policy"
)

type input struct {
	ID   string         `json:"id"`
	Text *string        `json:"text"`
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
}

type span struct {
	Unit  string `json:"unit"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Label string `json:"label"`
}

func main() {
	catalog := flag.String("catalog", "", "name catalog JSON (the corpus catalog)")
	flag.Parse()
	detectors, err := policy.Default().DetectorSet(*catalog)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	registry := domain.NewRegistry(detectors...)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var in input
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var ev domain.Event
		var units map[string]string
		if in.Text != nil {
			ev = domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostOpenCode, SessionID: in.ID, Text: *in.Text}
			units = map[string]string{"": *in.Text}
		} else {
			fields, text := domain.FlattenArgs(in.Args)
			tool := in.Tool
			if tool == "" {
				tool = "bash"
			}
			ev = domain.Event{Kind: domain.EventToolArgs, Host: domain.HostOpenCode, SessionID: in.ID, ToolName: tool, Text: text, Fields: fields, Args: in.Args}
			units = fields
		}
		spans := predict(registry.DetectAll(ev), units)
		if spans == nil {
			spans = []span{}
		}
		if err := out.Encode(map[string]any{"id": in.ID, "spans": spans}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// predict is a copy of the unexported internal/eval.predict: one
// left-to-right pass per unit preferring the longest match.
func predict(findings []domain.Finding, units map[string]string) []span {
	label := map[string]string{}
	var matches []string
	for _, f := range findings {
		if f.Category == "" || f.Match == "" {
			continue
		}
		if _, seen := label[f.Match]; !seen {
			label[f.Match] = f.Category
			matches = append(matches, f.Match)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i]) != len(matches[j]) {
			return len(matches[i]) > len(matches[j])
		}
		return matches[i] < matches[j]
	})
	var spans []span
	for unit, text := range units {
		for i := 0; i < len(text); {
			match := ""
			for _, m := range matches {
				if strings.HasPrefix(text[i:], m) {
					match = m
					break
				}
			}
			if match == "" {
				i++
				continue
			}
			start := utf8.RuneCountInString(text[:i])
			spans = append(spans, span{Unit: unit, Start: start, End: start + utf8.RuneCountInString(match), Label: label[match]})
			i += len(match)
		}
	}
	return spans
}
