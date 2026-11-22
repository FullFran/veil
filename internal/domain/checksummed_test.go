package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Synthetic values only: every check digit below was computed, not copied
// from a real company, card or person.

func detectWith(t *testing.T, d domain.Detector, text string) []domain.Finding {
	t.Helper()
	return d.Detect(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode, Text: text})
}

// wantOne asserts exactly one finding with the given category, match and key.
func wantOne(t *testing.T, findings []domain.Finding, detector, category, match, key string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (findings: %+v)", len(findings), findings)
	}
	f := findings[0]
	if f.Detector != detector || f.Category != category || f.Match != match || f.Key != key {
		t.Errorf("finding = {Detector:%q Category:%q Match:%q Key:%q}, want {%q %q %q %q}",
			f.Detector, f.Category, f.Match, f.Key, detector, category, match, key)
	}
	if f.Redacted == "" || f.Redacted == f.Match {
		t.Errorf("Redacted = %q, want a masked form of %q", f.Redacted, f.Match)
	}
}

func wantNone(t *testing.T, findings []domain.Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (findings: %+v)", len(findings), findings)
	}
}

// --- CIF ---

func TestCIFDetector_ValidDigitControl_Fires(t *testing.T) {
	// B + 1234567: even positions 2+4+6=12, odd positions doubled and
	// digit-summed 2+6+(1+0)+(1+4)=14, total 26, control (10-6)%10 = 4.
	wantOne(t, detectWith(t, domain.NewCIFDetector(), "Factura a nombre de B12345674, pagada."),
		"cif", "CIF", "B12345674", "")
}

func TestCIFDetector_ValidLetterControl_Fires(t *testing.T) {
	// P (public body) always takes a letter control: 0800000 gives 1, "B".
	wantOne(t, detectWith(t, domain.NewCIFDetector(), "El organismo P0800000B firma."),
		"cif", "CIF", "P0800000B", "")
}

func TestCIFDetector_Hyphenated_FiresWithCompactKey(t *testing.T) {
	wantOne(t, detectWith(t, domain.NewCIFDetector(), "CIF: G-8765432C"),
		"cif", "CIF", "G-8765432C", "G8765432C")
}

// Negative control: the right shape with the wrong control digit.
func TestCIFDetector_WrongControl_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewCIFDetector(), "Referencia B12345675 del pedido."))
}

// A (sociedad anónima) must carry a digit control and P a letter control:
// the right checksum in the wrong form is not a CIF.
func TestCIFDetector_ControlKindNotAllowedForLetter_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewCIFDetector(), "A5800002G y P08000002"))
}

func TestCIFDetector_GluedToLongerRun_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewCIFDetector(), "lote XB123456749 y B123456740"))
}

// --- Payment card ---

func TestCardDetector_ValidVisa_Fires(t *testing.T) {
	wantOne(t, detectWith(t, domain.NewCardDetector(), "Paga con la 4111111111111111 hoy."),
		"card", "TARJETA", "4111111111111111", "")
}

func TestCardDetector_GroupedWithSpaces_FiresWithCompactKey(t *testing.T) {
	wantOne(t, detectWith(t, domain.NewCardDetector(), "tarjeta 5555 5555 5555 4444, caduca pronto"),
		"card", "TARJETA", "5555 5555 5555 4444", "5555555555554444")
}

func TestCardDetector_AmexGroupedWithDashes_Fires(t *testing.T) {
	wantOne(t, detectWith(t, domain.NewCardDetector(), "Amex 3782-822463-10005."),
		"card", "TARJETA", "3782-822463-10005", "378282246310005")
}

// Negative control: one digit off, so Luhn fails.
func TestCardDetector_FailsLuhn_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewCardDetector(), "pedido 4111111111111112"))
}

// A Luhn-valid run with no card issuer prefix (here 1...) is an ordinary
// long number, not a card.
func TestCardDetector_NoIssuerPrefix_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewCardDetector(), "envío 1000000000000008"))
}

// Groups inside a longer run of groups (an IBAN body, a list of codes) are
// not a card, even when four of them pass Luhn.
func TestCardDetector_InsideLongerGroupRun_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewCardDetector(), "códigos 1234 4111 1111 1111 1111 y 5555 5555 5555 4444 9999"))
}

// --- NSS ---

func TestNSSDetector_ValidCompact_Fires(t *testing.T) {
	// Province 28, number 12345678: 2812345678 mod 97 = 40.
	wantOne(t, detectWith(t, domain.NewNSSDetector(), "Mi NSS es 281234567840."),
		"nss", "NSS", "281234567840", "")
}

func TestNSSDetector_SlashSeparated_FiresWithCompactKey(t *testing.T) {
	wantOne(t, detectWith(t, domain.NewNSSDetector(), "afiliación 08/87654321/46"),
		"nss", "NSS", "08/87654321/46", "088765432146")
}

// A number under ten million is padded as province*10^7 + number, so
// 46/00123456 checks against 460123456, not 4600123456.
func TestNSSDetector_SmallNumber_UsesShortForm(t *testing.T) {
	wantOne(t, detectWith(t, domain.NewNSSDetector(), "NSS 46 00123456 76"),
		"nss", "NSS", "46 00123456 76", "460012345676")
}

func TestNSSDetector_WrongControl_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewNSSDetector(), "factura 281234567841"))
}

func TestNSSDetector_UnknownProvince_DoesNotFire(t *testing.T) {
	// 99 is no province code, though 68 is the right mod-97 control for it.
	wantNone(t, detectWith(t, domain.NewNSSDetector(), "código 991234567868"))
}

func TestNSSDetector_GluedToLongerRun_DoesNotFire(t *testing.T) {
	wantNone(t, detectWith(t, domain.NewNSSDetector(), "serie 1281234567840 y 2812345678401"))
}

// --- through the registry ---

// Fullwidth digits fold to ASCII before the detectors run again, so the
// new detectors get the lookalike handling every detector has.
func TestRegistry_DetectAll_ChecksummedLookalikes(t *testing.T) {
	r := domain.NewRegistry(domain.NewCIFDetector(), domain.NewCardDetector(), domain.NewNSSDetector())
	findings, err := r.DetectAll(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode,
		Text: "Ｂ１２３４５６７４ ４１１１１１１１１１１１１１１１ ２８１２３４５６７８４０"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range findings {
		got[f.Category] = f.Key
	}
	want := map[string]string{"CIF": "B12345674", "TARJETA": "4111111111111111", "NSS": "281234567840"}
	for cat, key := range want {
		if got[cat] != key {
			t.Errorf("category %s: key %q, want %q (findings: %+v)", cat, got[cat], key, findings)
		}
	}
}
