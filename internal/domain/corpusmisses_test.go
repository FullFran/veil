package domain_test

import (
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Cases from issue #16: the misses the Spanish corpus baseline recorded.
// Each one goes through Detect and asserts the finding's span (Match),
// category and key. Values are synthetic.

type spanCase struct {
	text     string
	match    string
	category string
	key      string // "" means Match itself
}

func assertSingleSpan(t *testing.T, findings []domain.Finding, tc spanCase) {
	t.Helper()
	var got []domain.Finding
	for _, f := range findings {
		if f.Category == tc.category {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d %s findings, want 1: %+v", len(got), tc.category, findings)
	}
	if got[0].Match != tc.match {
		t.Errorf("Match = %q, want %q", got[0].Match, tc.match)
	}
	if got[0].Key != tc.key {
		t.Errorf("Key = %q, want %q", got[0].Key, tc.key)
	}
}

func promptEvent(text string) domain.Event {
	return domain.Event{Kind: domain.EventPromptSubmit, Text: text}
}

func TestIBANDetector_SeparatedForeignIBAN(t *testing.T) {
	cases := []spanCase{
		// iban-007: letter inside the BBAN, last group of three.
		{"Proveedor francés: FR14 2004 1010 0505 0001 3M02 606", "FR14 2004 1010 0505 0001 3M02 606", "IBAN", "FR1420041010050500013M02606"},
		{"Payee GB82 WEST 1234 5698 7654 32.", "GB82 WEST 1234 5698 7654 32", "IBAN", "GB82WEST12345698765432"},
		{"Konto DE89 3704 0044 0532 0130 00 bitte", "DE89 3704 0044 0532 0130 00", "IBAN", "DE89370400440532013000"},
		{"Cuenta PT50-0002-0123-1234-5678-9015-4.", "PT50-0002-0123-1234-5678-9015-4", "IBAN", "PT50000201231234567890154"},
		// A following digit group is not part of the IBAN: the cut at the
		// registry length keeps the Spanish behaviour.
		{"IBAN ES91 2100 0418 4502 0005 1332 7777", "ES91 2100 0418 4502 0005 1332", "IBAN", "ES9121000418450200051332"},
	}
	for _, tc := range cases {
		t.Run(tc.match, func(t *testing.T) {
			assertSingleSpan(t, domain.NewIBANDetector().Detect(promptEvent(tc.text)), tc)
		})
	}
}

func TestIBANDetector_SeparatedForeign_NearMisses(t *testing.T) {
	for _, text := range []string{
		"FR14 2004 1010 0505 0001 3M02 607",   // wrong check digits
		"FR14 2004 1010 0505 0001 3M02 60",    // shorter than the FR length
		"QQ14 2004 1010 0505 0001 3M02 606",   // not a registry country
		"FR14 2004 1010 0505 0001 3M02 606_x", // glued to a word
	} {
		t.Run(text, func(t *testing.T) {
			if findings := domain.NewIBANDetector().Detect(promptEvent(text)); len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestEmailDetector_UnicodeLocalPart(t *testing.T) {
	cases := []spanCase{
		// email-007
		{"Correo josé@dominio.example.es con tilde.", "josé@dominio.example.es", "EMAIL", ""},
		{"escribe a ñandú.pérez@correo.example.com, gracias", "ñandú.pérez@correo.example.com", "EMAIL", ""},
		{"IDN: maria@bücher.example.de.", "maria@bücher.example.de", "EMAIL", ""},
		{"user_name@example.com", "user_name@example.com", "EMAIL", ""},
	}
	for _, tc := range cases {
		t.Run(tc.match, func(t *testing.T) {
			assertSingleSpan(t, domain.NewEmailDetector().Detect(promptEvent(tc.text)), tc)
		})
	}
}

func TestEmailDetector_UnicodeNearMisses(t *testing.T) {
	for _, text := range []string{"josé@", "@dominio.es", "josé@dominio", "a@b.es2x"} {
		t.Run(text, func(t *testing.T) {
			if findings := domain.NewEmailDetector().Detect(promptEvent(text)); len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestPhoneDetector_ParenthesizedPrefix(t *testing.T) {
	cases := []spanCase{
		// tel-009
		{"Tel. (+34) 612 345 670", "(+34) 612 345 670", "TEL", "+34612345670"},
		{"Tel. (0034) 612-345-670.", "(0034) 612-345-670", "TEL", "+34612345670"},
		{"Tel. (+34)612345670", "(+34)612345670", "TEL", "+34612345670"},
		{"Tel. (+34) 612345670", "(+34) 612345670", "TEL", "+34612345670"},
	}
	for _, tc := range cases {
		t.Run(tc.match, func(t *testing.T) {
			assertSingleSpan(t, domain.NewPhoneDetector().Detect(promptEvent(tc.text)), tc)
		})
	}
}

func TestPhoneDetector_DotSeparated(t *testing.T) {
	cases := []spanCase{
		// tel-005
		{"Contacto 699.123.457.", "699.123.457", "TEL", "699123457"},
		{"Tel. +34 699.123.457", "+34 699.123.457", "TEL", "+34699123457"},
	}
	for _, tc := range cases {
		t.Run(tc.match, func(t *testing.T) {
			assertSingleSpan(t, domain.NewPhoneDetector().Detect(promptEvent(tc.text)), tc)
		})
	}
}

// The dot form collides with thousands separators; these amounts and
// longer numbers must stay untouched (tel-011 is the corpus guard).
func TestPhoneDetector_DotSeparated_AmountNearMisses(t *testing.T) {
	for _, text := range []string{
		"Importe total: 612.345.678,00 €",
		"Importe 612.345.678 €",
		"Importe 612.345.678 euros",
		"Importe EUR 612.345.678",
		"Saldo 1.612.345.678",
		"Saldo 612.345.678.901",
		"Saldo 612.345.678,5",
		"v612.345.678",
	} {
		t.Run(text, func(t *testing.T) {
			if findings := domain.NewPhoneDetector().Detect(promptEvent(text)); len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestNameCatalogDetector_JoinedSurnameExtendsSpan(t *testing.T) {
	d := domain.NewNameCatalogDetector([]string{"Juan García", "María Pérez", "Ana O'Neill"})
	cases := []spanCase{
		// nombre-009
		{"Habla con Juan García-López.", "Juan García-López", "NOMBRE", ""},
		{"Habla con JUAN GARCIA-LOPEZ-RUIZ.", "JUAN GARCIA-LOPEZ-RUIZ", "NOMBRE", ""},
		{"Habla con Juan García‐López.", "Juan García‐López", "NOMBRE", ""}, // U+2010
		{"Habla con Ana-María Pérez.", "Ana-María Pérez", "NOMBRE", ""},
		{"Habla con Juan García'Smith.", "Juan García'Smith", "NOMBRE", ""},
		{"Habla con Juan García’Smith.", "Juan García’Smith", "NOMBRE", ""}, // U+2019
		{"Habla con Ana O'Neill-Smith.", "Ana O'Neill-Smith", "NOMBRE", ""},
		// A joiner not followed by a letter is not part of the name.
		{"Habla con Juan García - López.", "Juan García", "NOMBRE", ""},
		{"Ref Juan García-2024.", "Juan García", "NOMBRE", ""},
		{"Lista: Juan García-", "Juan García", "NOMBRE", ""},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			assertSingleSpan(t, d.Detect(promptEvent(tc.text)), tc)
		})
	}
}

// TestPolicy_JoinedSurname_NoLeakNoSharedToken proves the extended name
// is one token of its own, different from the catalog entry's, and that
// no part of it is left in clear when both forms appear in one event,
// whatever order the substitutions run in.
func TestPolicy_JoinedSurname_NoLeakNoSharedToken(t *testing.T) {
	for i := 0; i < 50; i++ {
		registry := domain.NewRegistry(domain.NewNameCatalogDetector([]string{"Juan García"}))
		policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())
		decision, err := policy.Evaluate(domain.Event{
			Kind:      domain.EventPromptSubmit,
			Host:      domain.HostOpenCode,
			SessionID: "s1",
			Text:      "Juan García y Juan García-López",
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if decision.Kind != domain.Rewrite {
			t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
		}
		if strings.Contains(decision.RedactedText, "López") || strings.Contains(decision.RedactedText, "García") {
			t.Fatalf("RedactedText = %q leaks part of a name", decision.RedactedText)
		}
		parts := strings.Split(decision.RedactedText, " y ")
		if len(parts) != 2 || parts[0] == parts[1] {
			t.Fatalf("RedactedText = %q, want two distinct tokens", decision.RedactedText)
		}
	}
}
