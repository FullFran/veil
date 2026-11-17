package domain_test

import (
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Findings whose matches overlap in part (from one detector or several)
// must be replaced as one run: replacing either alone leaves the rest of
// the other in clear.
func TestPolicy_PartiallyOverlappingFindings_LeaveNothingInClear(t *testing.T) {
	const text = "Hola Ana Ruiz López fin, y Ruiz López y Ana Ruiz"
	cases := map[string][]domain.Finding{
		"left first":  {nameFinding("Ana Ruiz"), nameFinding("Ruiz López")},
		"right first": {nameFinding("Ruiz López"), nameFinding("Ana Ruiz")},
		"chain of three": {nameFinding("Ana Ruiz"), nameFinding("Ruiz López"),
			nameFinding("López fin")},
	}
	for name, findings := range cases {
		t.Run(name, func(t *testing.T) {
			registry := domain.NewRegistry()
			registry.RegisterFallible(fallibleStub{findings: findings})
			policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

			decision, err := policy.Evaluate(domain.Event{
				Kind: domain.EventToolArgs, Host: domain.HostClaudeCode, SessionID: "s",
				Text: text, Fields: map[string]string{"command": text},
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Kind != domain.Rewrite {
				t.Fatalf("decision = %+v, want a rewrite", decision)
			}
			for _, out := range []string{decision.RedactedText, decision.RedactedFields["command"]} {
				for _, part := range []string{"Ana", "Ruiz", "López"} {
					if strings.Contains(out, part) {
						t.Fatalf("rewritten %q leaves %q in clear", out, part)
					}
				}
			}
		})
	}
}
