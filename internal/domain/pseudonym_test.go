package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestMemoryPseudonymStore_SameOriginal_GetsSameToken proves the core
// contract: the same original value, in the same session and category,
// always gets the same stable token.
func TestMemoryPseudonymStore_SameOriginal_GetsSameToken(t *testing.T) {
	store := domain.NewMemoryPseudonymStore()

	first, err := store.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	second, err := store.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	if first != second {
		t.Fatalf("Token(...) = %q then %q, want the same token both times", first, second)
	}
	if first != "[DNI-001]" {
		t.Fatalf("Token(...) = %q, want [DNI-001]", first)
	}
}

// TestMemoryPseudonymStore_DifferentOriginals_GetDifferentTokens proves the
// per-category counter increments for a new original.
func TestMemoryPseudonymStore_DifferentOriginals_GetDifferentTokens(t *testing.T) {
	store := domain.NewMemoryPseudonymStore()

	first, _ := store.Token("session-1", "DNI", "12345678Z")
	second, _ := store.Token("session-1", "DNI", "87654321X")
	if first == second {
		t.Fatalf("both originals got the same token %q, want distinct tokens", first)
	}
	if second != "[DNI-002]" {
		t.Fatalf("second Token(...) = %q, want [DNI-002]", second)
	}
}

// TestMemoryPseudonymStore_DifferentSessions_AreIsolated proves a mapping
// in one session never leaks into another session's numbering or tokens.
func TestMemoryPseudonymStore_DifferentSessions_AreIsolated(t *testing.T) {
	store := domain.NewMemoryPseudonymStore()

	inSessionOne, _ := store.Token("session-1", "DNI", "12345678Z")
	inSessionTwo, _ := store.Token("session-2", "DNI", "12345678Z")
	if inSessionOne != "[DNI-001]" || inSessionTwo != "[DNI-001]" {
		t.Fatalf("got %q and %q, want both sessions to independently start at [DNI-001]", inSessionOne, inSessionTwo)
	}
}

// TestMemoryPseudonymStore_DifferentCategories_HaveIndependentCounters
// proves DNI-001 and IBAN-001 can coexist in the same session.
func TestMemoryPseudonymStore_DifferentCategories_HaveIndependentCounters(t *testing.T) {
	store := domain.NewMemoryPseudonymStore()

	dni, _ := store.Token("session-1", "DNI", "12345678Z")
	iban, _ := store.Token("session-1", "IBAN", "ES9121000418450200051332")
	if dni != "[DNI-001]" || iban != "[IBAN-001]" {
		t.Fatalf("got dni=%q iban=%q, want independent per-category counters", dni, iban)
	}
}
