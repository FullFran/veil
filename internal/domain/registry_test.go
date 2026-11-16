package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// stubDetector is a minimal domain.Detector used only to exercise Registry
// wiring, independent of any real detection logic.
type stubDetector struct {
	name     string
	findings []domain.Finding
}

func (s stubDetector) Name() string { return s.name }

func (s stubDetector) Detect(domain.Event) []domain.Finding { return s.findings }

func TestRegistry_DetectAll_ConcatenatesInOrder(t *testing.T) {
	first := stubDetector{name: "first", findings: []domain.Finding{{Detector: "first", Reason: "a"}}}
	second := stubDetector{name: "second", findings: []domain.Finding{{Detector: "second", Reason: "b"}, {Detector: "second", Reason: "c"}}}

	registry := domain.NewRegistry(first, second)
	findings := registry.DetectAll(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode})

	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}
	if findings[0].Reason != "a" || findings[1].Reason != "b" || findings[2].Reason != "c" {
		t.Fatalf("findings out of order: %+v", findings)
	}
}

func TestRegistry_DetectAll_NoFindings_ReturnsEmpty(t *testing.T) {
	registry := domain.NewRegistry(stubDetector{name: "quiet"})
	findings := registry.DetectAll(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode})

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestRegistry_Register_AddsDetector(t *testing.T) {
	registry := domain.NewRegistry()
	registry.Register(stubDetector{name: "late", findings: []domain.Finding{{Detector: "late", Reason: "z"}}})

	findings := registry.DetectAll(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode})
	if len(findings) != 1 || findings[0].Reason != "z" {
		t.Fatalf("findings = %+v, want a single finding with reason %q", findings, "z")
	}
}

func TestRegistry_Detectors_InRegistrationOrder(t *testing.T) {
	registry := domain.NewRegistry(stubDetector{name: "a"}, stubDetector{name: "b"})
	registry.Register(stubDetector{name: "c"})

	got := registry.Detectors()
	if len(got) != 3 || got[0].Name() != "a" || got[1].Name() != "b" || got[2].Name() != "c" {
		t.Fatalf("Detectors() = %v, want a, b, c", got)
	}
}
