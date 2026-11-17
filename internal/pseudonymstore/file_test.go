// Package pseudonymstore_test exercises the file-backed PseudonymStore
// adapter. Every test points FileStore at t.TempDir(), never a real
// XDG_STATE_HOME or the OS temp dir, so the suite never touches (or
// depends on) anything on the machine that runs it.
package pseudonymstore_test

import (
	"github.com/FullFran/veil/internal/pseudonymstore"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestFileStore_PersistsAcrossSeparateInstances proves the whole point of
// this adapter: veil's OpenCode shim spawns a fresh `veil` process per
// hook call, so the pseudonym mapping must survive past a single
// *FileStore instance's lifetime by living on disk, not only in memory.
func TestFileStore_PersistsAcrossSeparateInstances(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()

	first := newStore(t, dir, kr)
	token, err := first.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	if token != "[DNI-001]" {
		t.Fatalf("Token(...) = %q, want [DNI-001]", token)
	}

	// A brand new instance, as a separate `veil` process invocation would
	// construct, pointed at the same directory.
	second := newStore(t, dir, kr)
	again, err := second.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	if again != token {
		t.Fatalf("second instance Token(...) = %q, want the same token %q", again, token)
	}

	next, err := second.Token("session-1", "DNI", "87654321X")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	if next != "[DNI-002]" {
		t.Fatalf("Token(...) for a new original = %q, want [DNI-002]", next)
	}
}

// TestFileStore_DifferentSessions_UseSeparateFiles proves two sessions
// never share a mapping or a counter, and that each session's file is
// created with 0600 permissions: it holds a real client's identifiers, so
// it must not be world- or group-readable.
func TestFileStore_DifferentSessions_UseSeparateFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on windows")
	}

	dir := t.TempDir()
	kr := newFakeKeyring()
	store := newStore(t, dir, kr)

	if _, err := store.Token("session-1", "DNI", "12345678Z"); err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	tokenTwo, err := store.Token("session-2", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	if tokenTwo != "[DNI-001]" {
		t.Fatalf("session-2 Token(...) = %q, want [DNI-001] (isolated from session-1)", tokenTwo)
	}

	ids := filepath.Dir(pseudonymstore.SessionPath(dir, "session-1"))
	entries, err := os.ReadDir(ids)
	if err != nil {
		t.Fatalf("ReadDir(%s) failed: %v", ids, err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d files in %s, want 4 (a store and a counters file per session): %v", len(entries), dir, entries)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("Info() failed for %s: %v", entry.Name(), err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file %s has permissions %o, want 0600", entry.Name(), perm)
		}
	}
}

// TestFileStore_Original_ReversesAMintedToken_AcrossInstances proves
// rehydration works the same way Token does: a token minted by one
// *FileStore instance is reversible by a separate instance pointed at the
// same directory, since that is how veil's OpenCode shim actually calls
// this (a fresh process per hook).
func TestFileStore_Original_ReversesAMintedToken_AcrossInstances(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()

	first := newStore(t, dir, kr)
	token, err := first.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}

	second := newStore(t, dir, kr)
	original, found, err := second.Original("session-1", token)
	if err != nil {
		t.Fatalf("Original returned unexpected error: %v", err)
	}
	if !found {
		t.Fatal("Original reported not found for a token minted by a separate instance")
	}
	if original != "12345678Z" {
		t.Fatalf("Original(...) = %q, want %q", original, "12345678Z")
	}
}

// TestFileStore_Original_UnknownToken_ReportsNotFound proves an
// unrecognized token reports not-found rather than erroring.
func TestFileStore_Original_UnknownToken_ReportsNotFound(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	store := newStore(t, dir, kr)

	if _, err := store.Token("session-1", "DNI", "12345678Z"); err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}

	_, found, err := store.Original("session-1", "[DNI-999]")
	if err != nil {
		t.Fatalf("Original returned unexpected error: %v", err)
	}
	if found {
		t.Fatal("Original reported found for a token that was never minted")
	}
}

// TestFileStore_CorruptedSessionFile_FailsClosed proves a corrupted
// on-disk mapping produces an error instead of silently starting over
// (which could reuse a token number already sent to the model for a
// different original value).
func TestFileStore_CorruptedSessionFile_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	store := newStore(t, dir, kr)

	if _, err := store.Token("session-1", "DNI", "12345678Z"); err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}

	sessionFile := pseudonymstore.SessionPath(dir, "session-1") + ".age"
	if err := os.WriteFile(sessionFile, []byte("not json"), 0o600); err != nil {
		t.Fatalf("failed to corrupt fixture file: %v", err)
	}

	if _, err := store.Token("session-1", "DNI", "87654321X"); err == nil {
		t.Fatal("Token returned no error against a corrupted session file, want a fail-closed error")
	}
}

// TestFileStore_SessionFile_HoldsNoRealValueOrKey proves the store is
// encrypted at rest: after a rewrite, neither the real value nor the
// "category:original" mapping key appears anywhere in the bytes on disk.
func TestFileStore_SessionFile_HoldsNoRealValueOrKey(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())

	if _, err := store.Token("session-1", "EMAIL", "ana.garcia@example.com"); err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}

	ids := filepath.Dir(pseudonymstore.SessionPath(dir, "session-1"))
	entries, err := os.ReadDir(ids)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(ids, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile(%s) failed: %v", entry.Name(), err)
		}
		for _, secret := range []string{"ana.garcia@example.com", "EMAIL:ana", "example.com"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("%s holds %q in clear", entry.Name(), secret)
			}
		}
	}
}
