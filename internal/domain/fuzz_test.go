package domain_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Native Go fuzz tests (go test -fuzz) for the domain's handling of
// untrusted text: every prompt, tool argument and tool output a host sends
// reaches these functions. Without -fuzz they run their seed corpus as
// ordinary tests.

// fuzzRegistry is every detector veil ships, with a fixed name catalog.
func fuzzRegistry() *domain.Registry {
	return domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewIBANDetector(),
		domain.NewEmailDetector(),
		domain.NewPhoneDetector(),
		domain.NewSecretPathDetector(),
		domain.NewBinaryContentDetector(),
		domain.NewNameCatalogDetector([]string{"Juan García", "María Pérez"}),
	)
}

var fuzzSeeds = []string{
	"",
	"hola",
	"mi DNI es 12345678Z",
	"12.345.678-Z y ES91 2100 0418 4502 0005 1332",
	"llama al 612 345 678 o al +34612345678",
	"escribe a juan.garcia@example.com",
	"Juan García y María Pérez",
	"１２３４５６７８Ｚ",
	"cat ~/.ssh/id_rsa",
	"[DNI-001] ya es un marcador",
	"\x00\xff\xfe",
}

// FuzzPolicy_Evaluate: for any prompt text, Evaluate never panics or fails
// with an in-memory store; a Rewrite never carries a value a detector
// found, every marker it mints rehydrates to text that was in the input,
// and a Deny reason never quotes a found value.
func FuzzPolicy_Evaluate(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		registry := fuzzRegistry()
		policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())
		event := domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostClaudeCode, SessionID: "fuzz", Text: text}

		decision, err := policy.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", text, err)
		}
		findings, err := registry.DetectAll(event)
		if err != nil {
			t.Fatalf("DetectAll(%q): %v", text, err)
		}

		switch decision.Kind {
		case domain.Allow:
			if len(findings) != 0 {
				t.Fatalf("Evaluate(%q) allowed %d findings", text, len(findings))
			}
		case domain.Deny:
			for _, finding := range findings {
				if finding.Match != "" && strings.Contains(decision.Reason, finding.Match) {
					t.Fatalf("deny reason for %q quotes the found value %q", text, finding.Match)
				}
			}
		case domain.Rewrite:
			for _, finding := range findings {
				if finding.Match != "" && strings.Contains(decision.RedactedText, finding.Match) {
					t.Fatalf("rewrite of %q still carries the found value %q: %q", text, finding.Match, decision.RedactedText)
				}
			}
			for _, marker := range markerPattern.FindAllString(decision.RedactedText, -1) {
				if strings.Contains(text, marker) {
					continue // already in the input, not minted
				}
				original := rehydrate(t, policy, "fuzz", marker)
				if original == marker || !strings.Contains(text, original) {
					t.Fatalf("marker %s of %q rehydrates to %q, not to input text", marker, text, original)
				}
			}
		default:
			t.Fatalf("Evaluate(%q) returned decision kind %v", text, decision.Kind)
		}
	})
}

// FuzzFlattenRebuildArgs: for any JSON object of tool arguments, rebuilding
// it from its own flattened fields gives the same arguments back, and the
// text blob holds every field.
func FuzzFlattenRebuildArgs(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"command":"ls"}`,
		`{"a.b":"x","a":{"b":"y"}}`,
		`{"edits":[{"oldString":"a","newString":"12345678Z"}],"n":612345678,"ok":true,"none":null}`,
		`{"k\\.":{"":[1,2.5e3,"s"]}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var args map[string]any
		if err := domain.DecodeJSON(raw, &args); err != nil || args == nil {
			return
		}
		fields, text := domain.FlattenArgs(args)
		for key, value := range fields {
			if !strings.Contains(text, key+": "+value+"\n") {
				t.Fatalf("text blob of %s misses field %q", raw, key)
			}
		}
		if rebuilt := domain.RebuildArgs(args, fields); !reflect.DeepEqual(rebuilt, args) {
			t.Fatalf("RebuildArgs(FlattenArgs(%s)) = %#v, want the arguments back", raw, rebuilt)
		}
	})
}
