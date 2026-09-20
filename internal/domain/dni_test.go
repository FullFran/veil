package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

func detect(t *testing.T, text string) []domain.Finding {
	t.Helper()
	detector := domain.NewDNIDetector()
	event := domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode, Text: text}
	return detector.Detect(event)
}

func TestDNIDetector_ValidDNI_Fires(t *testing.T) {
	// 12345678Z is a well-known valid Spanish DNI: 12345678 mod 23 == 14,
	// and the 14th letter (0-indexed) of TRWAGMYFPDXBNJZSQVHLCKE is Z.
	findings := detect(t, "my DNI is 12345678Z, please remember it")
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (findings: %+v)", len(findings), findings)
	}
	if findings[0].Detector != "dni" {
		t.Errorf("Detector = %q, want %q", findings[0].Detector, "dni")
	}
}

func TestDNIDetector_ValidNIE_Fires(t *testing.T) {
	// X0000000T is a valid NIE: prefix X maps to 0, so the number is
	// 00000000, which mod 23 == 0, and the 0th control letter is T.
	findings := detect(t, "NIE: X0000000T")
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (findings: %+v)", len(findings), findings)
	}
}

// Negative control: this looks exactly like a DNI (8 digits + letter) but
// carries the wrong check letter. The correct letter for 12345678 is Z,
// not A. A detector validating with a bare regex instead of the real
// modulo-23 algorithm would wrongly fire here.
func TestDNIDetector_WrongCheckLetter_DoesNotFire(t *testing.T) {
	findings := detect(t, "reference code 12345678A for this ticket")
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (findings: %+v)", len(findings), findings)
	}
}

func TestDNIDetector_UnrelatedText_DoesNotFire(t *testing.T) {
	findings := detect(t, "the quarterly report is due on the 15th of March")
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (findings: %+v)", len(findings), findings)
	}
}

func TestDNIDetector_ShortNumberIsNotConfusedWithDNI(t *testing.T) {
	// A 9-digit run followed by a letter must not be parsed as an
	// 8-digit DNI plus a stray leading digit.
	findings := detect(t, "order number 123456789Z placed")
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (findings: %+v)", len(findings), findings)
	}
}

func TestDNIDetector_Name(t *testing.T) {
	if got := domain.NewDNIDetector().Name(); got != "dni" {
		t.Fatalf("Name() = %q, want %q", got, "dni")
	}
}
