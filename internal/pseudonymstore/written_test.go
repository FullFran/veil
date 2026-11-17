package pseudonymstore_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

// TestFileStore_TokenFor_RehydratesTheFirstWrittenForm: one token per
// canonical key, and Original gives back the first written form, also
// from a fresh process on the same store.
func TestFileStore_TokenFor_RehydratesTheFirstWrittenForm(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	store := newStore(t, dir, kr)

	first, err := store.TokenFor("session-1", "TEL", "+34612345678", "612 345 678")
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	second, err := store.TokenFor("session-1", "TEL", "+34612345678", "+34612345678")
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if first != "[TEL-001]" || second != first {
		t.Fatalf("tokens = %s, %s, want [TEL-001] twice", first, second)
	}

	reopened := newStore(t, dir, kr)
	original, found, err := reopened.Original("session-1", first)
	if err != nil || !found || original != "612 345 678" {
		t.Fatalf("Original = (%q, %v, %v), want (612 345 678, true, nil)", original, found, err)
	}
}

// TestFileStore_V2FileWithoutWrittenForms_RehydratesTheKey: a session file
// written before written forms were stored keeps its meaning: each marker
// rehydrates to its key, also after the key is seen written another way.
func TestFileStore_V2FileWithoutWrittenForms_RehydratesTheKey(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)
	kr := newFakeKeyring()
	kr.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = id.String()

	plain := `{"version":2,"mapping":{"TEL:612345678":"[TEL-001]","DNI:12345678Z":"[DNI-001]"},"reverse":{"[TEL-001]":"612345678","[DNI-001]":"12345678Z"},"counters":{"TEL":1,"DNI":1}}`
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session-1.age"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newStore(t, dir, kr)

	token, err := store.TokenFor("session-1", "DNI", "12345678Z", "12.345.678-Z")
	if err != nil || token != "[DNI-001]" {
		t.Fatalf("TokenFor = (%q, %v), want ([DNI-001], nil)", token, err)
	}
	for marker, want := range map[string]string{"[TEL-001]": "612345678", "[DNI-001]": "12345678Z"} {
		original, found, err := store.Original("session-1", marker)
		if err != nil || !found || original != want {
			t.Errorf("Original(%s) = (%q, %v, %v), want (%q, true, nil)", marker, original, found, err, want)
		}
	}
}
