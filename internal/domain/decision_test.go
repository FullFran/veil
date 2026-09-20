package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

func TestAllowDecision(t *testing.T) {
	d := domain.AllowDecision()
	if d.Kind != domain.Allow {
		t.Fatalf("Kind = %v, want Allow", d.Kind)
	}
	if d.Reason != "" {
		t.Fatalf("Reason = %q, want empty", d.Reason)
	}
}

func TestDenyDecision(t *testing.T) {
	d := domain.DenyDecision("Spanish DNI detected")
	if d.Kind != domain.Deny {
		t.Fatalf("Kind = %v, want Deny", d.Kind)
	}
	if d.Reason != "Spanish DNI detected" {
		t.Fatalf("Reason = %q, want %q", d.Reason, "Spanish DNI detected")
	}
}

func TestRewriteDecision(t *testing.T) {
	fields := map[string]string{"file_path": "***REDACTED***"}
	d := domain.RewriteDecision("***REDACTED***", fields)
	if d.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", d.Kind)
	}
	if d.RedactedText != "***REDACTED***" {
		t.Fatalf("RedactedText = %q, want %q", d.RedactedText, "***REDACTED***")
	}
	if d.RedactedFields["file_path"] != "***REDACTED***" {
		t.Fatalf("RedactedFields[file_path] = %q, want %q", d.RedactedFields["file_path"], "***REDACTED***")
	}
}

func TestDecisionKind_String(t *testing.T) {
	tests := map[domain.DecisionKind]string{
		domain.Allow:   "Allow",
		domain.Deny:    "Deny",
		domain.Rewrite: "Rewrite",
	}
	for kind, want := range tests {
		if got := kind.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", kind, got, want)
		}
	}
}
