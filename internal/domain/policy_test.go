package domain_test

import (
	"errors"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

func TestPolicy_Evaluate_NoFindings_Allows(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry())
	decision, err := policy.Evaluate(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode, Text: "nothing to see here"})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Allow {
		t.Fatalf("Kind = %v, want Allow", decision.Kind)
	}
}

func TestPolicy_Evaluate_WithFindings_Denies(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry)

	decision, err := policy.Evaluate(domain.Event{
		Kind: domain.EventToolArgs,
		Host: domain.HostClaudeCode,
		Text: "DNI 12345678Z",
	})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("Kind = %v, want Deny", decision.Kind)
	}
	if decision.Reason == "" {
		t.Fatal("Reason must not be empty on a Deny decision")
	}
}

// TestPolicy_Evaluate_UnsupportedCapability_ErrorsInsteadOfDeciding proves
// that Evaluate refuses to render any verdict (Allow, Deny or Rewrite) for
// an event whose host cannot actually enforce the resulting decision.
func TestPolicy_Evaluate_UnsupportedCapability_ErrorsInsteadOfDeciding(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry)

	decision, err := policy.Evaluate(domain.Event{
		Kind: domain.EventPromptSubmit,
		Host: domain.HostOpenCode,
		Text: "DNI 12345678Z",
	})

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error = %v, want *domain.UnsupportedCapabilityError", err)
	}
	if decision.Kind != domain.Unknown || decision.Reason != "" || decision.RedactedText != "" || decision.RedactedFields != nil {
		t.Fatalf("decision = %+v, want the zero Decision", decision)
	}
}

func TestPolicy_Evaluate_UnsupportedCapability_ChecksEvenWithoutFindings(t *testing.T) {
	// Capability must be checked before running detectors: even a
	// perfectly clean prompt must not be silently "allowed" on a host
	// that has no way to have blocked it if it had not been clean.
	policy := domain.NewPolicy(domain.NewRegistry())

	_, err := policy.Evaluate(domain.Event{
		Kind: domain.EventPromptSubmit,
		Host: domain.HostOpenCode,
		Text: "nothing sensitive here at all",
	})

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error = %v, want *domain.UnsupportedCapabilityError", err)
	}
}
