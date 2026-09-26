package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestIBANDetector_ValidIBAN_IsDetected proves the detector recognizes a
// real, checksum-valid IBAN and tags it as a rewritable finding (Category
// "IBAN"), carrying the exact matched text so the policy can substitute a
// stable pseudonym for it.
func TestIBANDetector_ValidIBAN_IsDetected(t *testing.T) {
	d := domain.NewIBANDetector()
	event := domain.Event{
		Kind: domain.EventPromptSubmit,
		Text: "my IBAN is ES9121000418450200051332, please remember it",
	}

	findings := d.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Match != "ES9121000418450200051332" {
		t.Errorf("Match = %q, want the exact IBAN", f.Match)
	}
	if f.Category != "IBAN" {
		t.Errorf("Category = %q, want %q", f.Category, "IBAN")
	}
	if f.Detector != "iban" {
		t.Errorf("Detector = %q, want %q", f.Detector, "iban")
	}
}

// TestIBANDetector_InvalidChecksum_IsIgnored proves a string shaped like an
// IBAN but with the wrong mod-97 check digits does not fire: a detector
// that fires on every IBAN-shaped string is as useless as one that never
// fires.
func TestIBANDetector_InvalidChecksum_IsIgnored(t *testing.T) {
	d := domain.NewIBANDetector()
	event := domain.Event{
		Kind: domain.EventPromptSubmit,
		Text: "not an IBAN: ES0000000000000000000000",
	}

	findings := d.Detect(event)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

// TestIBANDetector_CleanText_IsIgnored is the negative control.
func TestIBANDetector_CleanText_IsIgnored(t *testing.T) {
	d := domain.NewIBANDetector()
	event := domain.Event{Kind: domain.EventPromptSubmit, Text: "no financial data here"}

	if findings := d.Detect(event); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}
