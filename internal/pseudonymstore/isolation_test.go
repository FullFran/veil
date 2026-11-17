package pseudonymstore_test

import (
	"errors"
	"testing"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

// collidingIDs held one store file each before #26: the old sanitizer
// mapped all of them to the stem a_b.
var collidingIDs = []string{"a/b", `a\b`, "a..b", "a_b"}

// TestFileStore_DistinctSessionIDs_NeverShareAMapping proves that ids
// the old file naming conflated (a/b, a\b, a..b and a_b; unknown-session
// and the old empty id) never share a mapping, a counters file or a
// forget: a marker minted in one is unknown in every other, each counts
// from 001, and forgetting one leaves the others intact.
func TestFileStore_DistinctSessionIDs_NeverShareAMapping(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())

	values := map[string]string{"a/b": "12345678Z", `a\b`: "87654321X", "a..b": "11111111H", "a_b": "22222222J", "unknown-session": "33333333P"}
	ids := append(append([]string{}, collidingIDs...), "unknown-session")
	tokens := map[string]string{}
	for _, id := range ids {
		tok, err := store.Token(id, "DNI", values[id])
		if err != nil {
			t.Fatalf("Token(%q): %v", id, err)
		}
		if tok != "[DNI-001]" {
			t.Errorf("Token(%q) = %q, want [DNI-001] (own counters)", id, tok)
		}
		tokens[id] = tok
	}
	for _, id := range ids {
		got, ok, err := store.Original(id, tokens[id])
		if err != nil || !ok || got != values[id] {
			t.Errorf("Original(%q) = %q, %v, %v; want its own value", id, got, ok, err)
		}
	}

	if err := store.Forget("a/b"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	for _, id := range ids[1:] {
		if got, ok, err := store.Original(id, tokens[id]); err != nil || !ok || got != values[id] {
			t.Errorf("after Forget(a/b), Original(%q) = %q, %v, %v; want it kept", id, got, ok, err)
		}
	}
	if _, ok, _ := store.Original("a/b", tokens["a/b"]); ok {
		t.Error("Forget(a/b) left its mapping")
	}
}

// TestFileStore_EmptySessionID_FailsClosed proves an empty session id
// never reaches a shared bucket: every per-session operation refuses it
// with ErrSessionIDMissing.
func TestFileStore_EmptySessionID_FailsClosed(t *testing.T) {
	store := newStore(t, t.TempDir(), newFakeKeyring())

	_, err := store.Token("", "DNI", "12345678Z")
	wantErr(t, err, pseudonymstore.ErrSessionIDMissing)
	_, _, err = store.Original("", "[DNI-001]")
	wantErr(t, err, pseudonymstore.ErrSessionIDMissing)
	_, err = store.Reveal("")
	wantErr(t, err, pseudonymstore.ErrSessionIDMissing)
	if err := store.Forget(""); !errors.Is(err, pseudonymstore.ErrSessionIDMissing) {
		t.Fatalf("Forget(\"\") = %v, want ErrSessionIDMissing", err)
	}
}
