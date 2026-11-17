package domain_test

import (
	"regexp"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

var markerPattern = regexp.MustCompile(`\[[A-Z]+-\d{3}\]`)

// TestPolicy_Rehydration_WritesTheFirstWrittenForm: a marker's identity is
// the canonical key (E.164 for a phone, the compact form of a separated
// DNI or IBAN, the NFKC form of a lookalike), but rehydration writes back
// the first form the session saw written for it, so an edit whose old text
// carries the marker matches the bytes of the file the model read.
func TestPolicy_Rehydration_WritesTheFirstWrittenForm(t *testing.T) {
	cases := []struct {
		name   string
		texts  []string // events of one session, in order
		marker string
		want   string
	}{
		{"bare phone", []string{"612345678"}, "[TEL-001]", "612345678"},
		{"separated phone, then E.164", []string{"612 345 678", "+34612345678"}, "[TEL-001]", "612 345 678"},
		{"E.164, then bare phone", []string{"+34612345678", "612345678"}, "[TEL-001]", "+34612345678"},
		{"two forms in one event, text order", []string{"612 345 678 o +34612345678"}, "[TEL-001]", "612 345 678"},
		{"separated DNI, then compact", []string{"12.345.678-Z", "12345678Z"}, "[DNI-001]", "12.345.678-Z"},
		{"separated IBAN, then compact", []string{"ES91 2100 0418 4502 0005 1332", "ES9121000418450200051332"}, "[IBAN-001]", "ES91 2100 0418 4502 0005 1332"},
		{"full-width DNI, then plain", []string{"１２３４５６７８Ｚ", "12345678Z"}, "[DNI-001]", "１２３４５６７８Ｚ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := domain.NewRegistry(domain.NewDNIDetector(), domain.NewIBANDetector(), domain.NewPhoneDetector())
			policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())
			for _, text := range tc.texts {
				decision, err := policy.Evaluate(domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostOpenCode, SessionID: "s1", Text: text})
				if err != nil {
					t.Fatalf("Evaluate %q: %v", text, err)
				}
				markers := markerPattern.FindAllString(decision.RedactedText, -1)
				if decision.Kind != domain.Rewrite || len(markers) == 0 {
					t.Fatalf("%q -> %q, want it pseudonymized as %s", text, decision.RedactedText, tc.marker)
				}
				for _, m := range markers {
					if m != tc.marker {
						t.Fatalf("%q -> %q, want only %s", text, decision.RedactedText, tc.marker)
					}
				}
			}
			if got := rehydrate(t, policy, "s1", tc.marker); got != tc.want {
				t.Errorf("%s rehydrates to %q, want %q", tc.marker, got, tc.want)
			}
		})
	}
}

// TestMemoryPseudonymStore_TokenFor_KeepsTheFirstWrittenForm pins the
// store contract: one token per key, rehydrated to the first written form.
func TestMemoryPseudonymStore_TokenFor_KeepsTheFirstWrittenForm(t *testing.T) {
	store := domain.NewMemoryPseudonymStore()
	first, err := store.TokenFor("s1", "TEL", "+34612345678", "612 345 678")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.TokenFor("s1", "TEL", "+34612345678", "+34612345678")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("tokens = %s, %s, want one token per key", first, second)
	}
	original, found, err := store.Original("s1", first)
	if err != nil || !found || original != "612 345 678" {
		t.Fatalf("Original = (%q, %v, %v), want (612 345 678, true, nil)", original, found, err)
	}
}
