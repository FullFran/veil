package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestPhoneDetector_SpanishNumbers_AreDetected covers the bare 9-digit
// form and the +34 country-code form, with and without an internal space.
func TestPhoneDetector_SpanishNumbers_AreDetected(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"bare 9-digit mobile", "call me at 612345678 tomorrow", "612345678"},
		{"plus34 with space", "call me at +34 612345678 tomorrow", "+34 612345678"},
		{"plus34 no space", "call me at +34612345678 tomorrow", "+34612345678"},
		{"landline starting 9", "office line is 912345678", "912345678"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := domain.NewPhoneDetector()
			findings := d.Detect(domain.Event{Kind: domain.EventPromptSubmit, Text: tc.text})
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			if findings[0].Match != tc.want {
				t.Errorf("Match = %q, want %q", findings[0].Match, tc.want)
			}
			if findings[0].Category != "TEL" {
				t.Errorf("Category = %q, want %q", findings[0].Category, "TEL")
			}
		})
	}
}

// TestPhoneDetector_NonSpanishLookingNumbers_AreIgnored is the negative
// control: an 8-digit number and a 9-digit number starting with 5 (not a
// valid Spanish mobile/landline prefix) must not fire.
func TestPhoneDetector_NonSpanishLookingNumbers_AreIgnored(t *testing.T) {
	d := domain.NewPhoneDetector()

	for _, text := range []string{"reference number 12345678", "order 512345678 shipped"} {
		if findings := d.Detect(domain.Event{Kind: domain.EventPromptSubmit, Text: text}); len(findings) != 0 {
			t.Errorf("text %q: got %d findings, want 0: %+v", text, len(findings), findings)
		}
	}
}
