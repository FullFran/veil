package evidence_test

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/eval"
	"github.com/FullFran/veil/internal/evidence"
	"github.com/FullFran/veil/internal/policy"
)

// markerPattern matches a veil pseudonym token. A token derives from
// content, so no record may carry one.
var markerPattern = regexp.MustCompile(`\[[A-Z]+-[0-9]{3}\]`)

var jsonLiterals = map[string]bool{"true": true, "false": true, "null": true}

// leakForms returns every form a detected value must never appear in: in
// clear, lowercased and compacted (spaces, dots and dashes removed).
func leakForms(value string) []string {
	compact := strings.NewReplacer(" ", "", ".", "", "-", "").Replace(value)
	forms := []string{value, strings.ToLower(value), compact, strings.ToLower(compact)}
	return forms
}

// assertNoLeak fails if record, as serialized JSON, contains any form of
// any of values, or any pseudonym marker. Values shorter than 4 runes and
// the JSON literals a unit may hold for a boolean argument are skipped:
// they identify no one and match the record's own JSON syntax.
func assertNoLeak(t *testing.T, label string, record []byte, values []string) {
	t.Helper()
	s := string(record)
	if m := markerPattern.FindString(s); m != "" {
		t.Errorf("%s: record carries the pseudonym marker %q", label, m)
	}
	for _, v := range values {
		for _, form := range leakForms(v) {
			if len([]rune(form)) < 4 || jsonLiterals[form] {
				continue
			}
			if strings.Contains(s, form) {
				t.Errorf("%s: record carries input text %q", label, form)
			}
		}
	}
}

// policyWith returns a policy enabling every detector with action, so the
// leak test covers rewrite and deny paths alike.
func policyWith(t *testing.T, action string) *policy.Policy {
	t.Helper()
	doc := `{"version":"1.0","detectors":{` +
		`"dni":{"action":"` + action + `"},"iban":{"action":"` + action + `"},` +
		`"email":{"action":"` + action + `"},"phone":{"action":"` + action + `"},` +
		`"name-catalog":{"action":"` + action + `"},` +
		`"secret-path":{"action":"deny"},"binary-content":{"action":"deny"}}}`
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

// TestCorpus_NoEvidenceLeaks runs every case of the Spanish evaluation
// corpus through the full decision path (rewrite and deny policies, both
// hosts) and checks that no evidence record carries any gold value, any
// finding's match or key, any unit text, or any pseudonym marker.
func TestCorpus_NoEvidenceLeaks(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "corpus", "es", "v1")
	corpus, err := eval.LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("empty corpus")
	}

	checked := 0
	for _, action := range []string{"rewrite", "deny"} {
		p := policyWith(t, action)
		registry, err := p.Registry(corpus.CatalogPath)
		if err != nil {
			t.Fatal(err)
		}
		evaluator := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

		for _, cs := range corpus.Cases {
			for _, host := range []domain.Host{domain.HostClaudeCode, domain.HostOpenCode} {
				event := cs.Event
				event.Host = host
				event.SessionID = "corpus-session"
				decision, err := evaluator.Evaluate(event)
				if err != nil {
					t.Fatalf("%s/%s/%s: Evaluate: %v", action, host, cs.ID, err)
				}
				findings, err := registry.DetectAll(event)
				if err != nil {
					t.Fatal(err)
				}
				rec, err := evidence.Build(evidence.Input{
					ID:            "00000000-0000-4000-8000-000000000000",
					Time:          fixedTime,
					Host:          host,
					Event:         event.Kind,
					Tool:          event.ToolName,
					Session:       event.SessionID,
					Action:        decision.Kind,
					Findings:      findings,
					PolicyDigest:  p.Digest(),
					PolicyVersion: p.Version,
				})
				if err != nil {
					t.Fatalf("%s/%s: Build: %v", action, cs.ID, err)
				}
				b, err := json.Marshal(rec)
				if err != nil {
					t.Fatal(err)
				}

				var values []string
				for _, g := range cs.Gold {
					values = append(values, string([]rune(cs.Units[g.Unit])[g.Start:g.End]))
				}
				for _, f := range findings {
					values = append(values, f.Match, f.Key, f.Redacted)
				}
				for _, text := range cs.Units {
					values = append(values, text)
				}
				values = append(values, decision.RedactedText)
				for _, v := range decision.RedactedFields {
					values = append(values, v)
				}
				assertNoLeak(t, action+"/"+string(host)+"/"+cs.ID, b, values)
				checked++
			}
		}
	}
	if checked != 4*len(corpus.Cases) {
		t.Fatalf("checked %d records, want %d", checked, 4*len(corpus.Cases))
	}
}
