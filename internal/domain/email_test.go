package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestEmailDetector_ValidEmail_IsDetected proves the detector recognizes an
// email address and tags it as a rewritable finding (Category "EMAIL").
func TestEmailDetector_ValidEmail_IsDetected(t *testing.T) {
	d := domain.NewEmailDetector()
	event := domain.Event{
		Kind: domain.EventPromptSubmit,
		Text: "contact me at maria.perez@tecnisan.es for details",
	}

	findings := d.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Match != "maria.perez@tecnisan.es" {
		t.Errorf("Match = %q, want the exact email", f.Match)
	}
	if f.Category != "EMAIL" {
		t.Errorf("Category = %q, want %q", f.Category, "EMAIL")
	}
	if f.Detector != "email" {
		t.Errorf("Detector = %q, want %q", f.Detector, "email")
	}
}

// TestEmailDetector_CleanText_IsIgnored is the negative control.
func TestEmailDetector_CleanText_IsIgnored(t *testing.T) {
	d := domain.NewEmailDetector()
	event := domain.Event{Kind: domain.EventPromptSubmit, Text: "no contact info here"}

	if findings := d.Detect(event); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}
