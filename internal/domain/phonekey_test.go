package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// e164 is the ITU-T E.164 form every written form of the test phone keys as.
const e164 = "+34612345678"

// phoneWrittenForms are the ways one Spanish phone is written: bare, with
// the country code as "+34", "0034", "(+34)" or "(0034)", compact or
// grouped by spaces, dots or dashes.
var phoneWrittenForms = []string{
	"612345678",
	"+34612345678",
	"+34 612345678",
	"0034612345678",
	"(+34)612345678",
	"(+34) 612345678",
	"(0034) 612345678",
	"(+34) 612-345-678",
	"+34 612 345 678",
	"0034 612 345 678",
	"(0034) 612 34 56 78",
	"612 345 678",
	"612-345-678",
	"612.345.678",
	"612 34 56 78",
	"612-34-56-78",
}

// TestPhoneDetector_EveryWrittenForm_KeysAsE164 pins the canonical key of a
// Spanish phone: whatever its written form, one finding covering exactly
// that form, keyed as E.164.
func TestPhoneDetector_EveryWrittenForm_KeysAsE164(t *testing.T) {
	d := domain.NewPhoneDetector()
	for _, form := range phoneWrittenForms {
		t.Run(form, func(t *testing.T) {
			findings := d.Detect(domain.Event{Kind: domain.EventPromptSubmit, Text: "Tel: " + form + "."})
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			if findings[0].Match != form {
				t.Errorf("Match = %q, want the written form %q", findings[0].Match, form)
			}
			if findings[0].Key != e164 {
				t.Errorf("Key = %q, want %q", findings[0].Key, e164)
			}
		})
	}
}

// TestPhoneDetector_CompactPrefixGluedToAWord_IsIgnored keeps the new
// compact "0034" form from firing inside a longer identifier or number.
func TestPhoneDetector_CompactPrefixGluedToAWord_IsIgnored(t *testing.T) {
	d := domain.NewPhoneDetector()
	for _, text := range []string{"ref0034612345678", "10034612345678", "00346123456789", "_0034612345678"} {
		t.Run(text, func(t *testing.T) {
			if findings := d.Detect(domain.Event{Kind: domain.EventPromptSubmit, Text: text}); len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

// rehydrate returns what a write tool receives for content in session.
func rehydrate(t *testing.T, policy *domain.Policy, session, content string) string {
	t.Helper()
	write, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostOpenCode,
		SessionID: session,
		ToolName:  "write",
		Text:      "content=" + content,
		Fields:    map[string]string{"content": content},
	})
	if err != nil {
		t.Fatalf("Evaluate write: %v", err)
	}
	return write.RedactedFields["content"]
}

// TestPolicy_OnePhoneEveryForm_OneMarker is issue #27: the same phone
// written bare and with its country code is one contact to the model, and
// the marker rehydrates to the first form written.
func TestPolicy_OnePhoneEveryForm_OneMarker(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewPhoneDetector()), domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostOpenCode,
		SessionID: "s1",
		Text:      "a 612345678 b +34 612 345 678 c 0034612345678 d (+34) 612-345-678",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
	}
	if want := "a [TEL-001] b [TEL-001] c [TEL-001] d [TEL-001]"; decision.RedactedText != want {
		t.Errorf("RedactedText = %q, want %q", decision.RedactedText, want)
	}
	if got := rehydrate(t, policy, "s1", "[TEL-001]"); got != "612345678" {
		t.Errorf("[TEL-001] rehydrates to %q, want the first written form 612345678", got)
	}
}

// TestPolicy_ExistingSessionPhoneMarkers_KeepTheirMeaning covers a session
// whose store already holds a phone under the old bare key: that marker is
// never merged or renumbered and still rehydrates to what it was minted
// for; the number seen again gets a new marker keyed by its E.164 form.
func TestPolicy_ExistingSessionPhoneMarkers_KeepTheirMeaning(t *testing.T) {
	store := domain.NewMemoryPseudonymStore()
	old, err := store.Token("s1", "TEL", "612345678")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if old != "[TEL-001]" {
		t.Fatalf("seed token = %q, want [TEL-001]", old)
	}
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewPhoneDetector()), store)

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostOpenCode,
		SessionID: "s1",
		Text:      "612345678 y +34 612 345 678",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if want := "[TEL-002] y [TEL-002]"; decision.RedactedText != want {
		t.Errorf("RedactedText = %q, want %q", decision.RedactedText, want)
	}
	if got := rehydrate(t, policy, "s1", "[TEL-001]"); got != "612345678" {
		t.Errorf("[TEL-001] rehydrates to %q, want the value it was minted for", got)
	}
	if got := rehydrate(t, policy, "s1", "[TEL-002]"); got != "612345678" {
		t.Errorf("[TEL-002] rehydrates to %q, want its first written form 612345678", got)
	}
}
