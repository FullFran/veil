package domain_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// fallibleStub is a domain.FallibleDetector that returns fixed findings
// or a fixed error and counts its calls.
type fallibleStub struct {
	findings []domain.Finding
	err      error
	calls    *int
}

func (s fallibleStub) Name() string { return "fallible" }

func (s fallibleStub) Detect(domain.Event) ([]domain.Finding, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.findings, s.err
}

var errStub = errors.New("stub detector failed")

func nameFinding(match string) domain.Finding {
	return domain.Finding{Detector: "fallible", Reason: "r", Redacted: "[NOMBRE]", Match: match, Category: "NOMBRE"}
}

func TestRegistry_FallibleDetector_FindingsFollowPlainOnes(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	registry.RegisterFallible(fallibleStub{findings: []domain.Finding{nameFinding("Ana Ruiz")}})

	findings, err := registry.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: "Ana Ruiz 12345678Z"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Detector != "dni" || findings[1].Detector != "fallible" {
		t.Fatalf("findings = %+v, want dni then fallible", findings)
	}
}

func TestRegistry_FallibleDetector_ErrorFailsDetection(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	registry.RegisterFallible(fallibleStub{err: errStub})

	findings, err := registry.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: "12345678Z"})
	if !errors.Is(err, errStub) {
		t.Fatalf("err = %v, want the detector's error", err)
	}
	if findings != nil {
		t.Fatalf("findings = %+v, want none on failure", findings)
	}
}

func TestRegistry_FallibleDetector_RunsOnLookalikeView(t *testing.T) {
	calls := 0
	registry := domain.NewRegistry()
	registry.RegisterFallible(fallibleStub{calls: &calls})

	// U+FF21 is a full-width "A": the text needs a lookalike view.
	if _, err := registry.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: "Ａna"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (raw text and lookalike view)", calls)
	}
}

func TestRegistry_FallibleDetector_ErrorOnLookalikeViewFailsDetection(t *testing.T) {
	calls := 0
	registry := domain.NewRegistry()
	registry.RegisterFallible(failSecond{calls: &calls})

	if _, err := registry.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: "Ａna"}); !errors.Is(err, errStub) {
		t.Fatalf("err = %v, want the detector's error from the lookalike pass", err)
	}
}

// failSecond succeeds on its first call and fails on every later one.
type failSecond struct{ calls *int }

func (failSecond) Name() string { return "fallible" }

func (s failSecond) Detect(domain.Event) ([]domain.Finding, error) {
	*s.calls++
	if *s.calls > 1 {
		return nil, errStub
	}
	return nil, nil
}

func TestPolicy_FallibleDetectorError_FailsClosed(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	registry.RegisterFallible(fallibleStub{err: errStub})
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostClaudeCode, SessionID: "s", Text: "hola"})
	if !errors.Is(err, errStub) {
		t.Fatalf("err = %v, want the detector's error", err)
	}
	if !reflect.DeepEqual(decision, domain.Decision{}) {
		t.Fatalf("decision = %+v, want the zero decision on failure", decision)
	}
}

func TestPolicy_Assess_ReturnsTheFindingsItDecidedOn(t *testing.T) {
	calls := 0
	registry := domain.NewRegistry()
	registry.RegisterFallible(fallibleStub{findings: []domain.Finding{nameFinding("Ana Ruiz")}, calls: &calls})
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, findings, err := policy.Assess(domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostClaudeCode, SessionID: "s", Text: "Soy Ana Ruiz"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Kind != domain.Rewrite || decision.RedactedText != "Soy [NOMBRE-001]" {
		t.Fatalf("decision = %+v, want a rewrite of the name", decision)
	}
	if len(findings) != 1 || findings[0].Detector != "fallible" {
		t.Fatalf("findings = %+v, want the one finding the decision used", findings)
	}
	if calls != 1 {
		t.Fatalf("detector calls = %d, want 1: evidence must reuse the evaluation's findings", calls)
	}
}
