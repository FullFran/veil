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

// TestZeroValueDecision_IsNotAllow guards against a specific, easy-to-miss
// bug class: if Allow were DecisionKind(0), an accidentally zero-valued
// Decision (e.g. returned alongside an error, or from a forgotten return
// path) would silently read as an explicit Allow. That is exactly the
// silent-downgrade failure mode this project exists to prevent, so the
// zero value must be a distinct, non-actionable Unknown.
func TestZeroValueDecision_IsNotAllow(t *testing.T) {
	var zero domain.Decision
	if zero.Kind == domain.Allow {
		t.Fatal("the zero value of Decision must not equal Allow")
	}
	if zero.Kind != domain.Unknown {
		t.Fatalf("zero.Kind = %v, want Unknown", zero.Kind)
	}
}
