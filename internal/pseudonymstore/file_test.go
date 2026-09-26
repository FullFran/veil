// Package pseudonymstore_test exercises the file-backed PseudonymStore
// adapter. Every test points FileStore at t.TempDir(), never a real
// XDG_STATE_HOME or the OS temp dir, so the suite never touches (or
// depends on) anything on the machine that runs it.
package pseudonymstore_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

// TestFileStore_PersistsAcrossSeparateInstances proves the whole point of
// this adapter: veil's OpenCode shim spawns a fresh `veil` process per
// hook call, so the pseudonym mapping must survive past a single
// *FileStore instance's lifetime by living on disk, not only in memory.
func TestFileStore_PersistsAcrossSeparateInstances(t *testing.T) {
	dir := t.TempDir()

	first := pseudonymstore.NewFileStore(dir)
	token, err := first.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	if token != "[DNI-001]" {
		t.Fatalf("Token(...) = %q, want [DNI-001]", token)
	}

	// A brand new instance, as a separate `veil` process invocation would
	// construct, pointed at the same directory.
	second := pseudonymstore.NewFileStore(dir)
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
	store := pseudonymstore.NewFileStore(dir)

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

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s) failed: %v", dir, err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d files in %s, want 2 (one per session): %v", len(entries), dir, entries)
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

// TestFileStore_CorruptedSessionFile_FailsClosed proves a corrupted
// on-disk mapping produces an error instead of silently starting over
// (which could reuse a token number already sent to the model for a
// different original value).
func TestFileStore_CorruptedSessionFile_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	store := pseudonymstore.NewFileStore(dir)

	if _, err := store.Token("session-1", "DNI", "12345678Z"); err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}

	sessionFile := filepath.Join(dir, "session-1.json")
	if err := os.WriteFile(sessionFile, []byte("not json"), 0o600); err != nil {
		t.Fatalf("failed to corrupt fixture file: %v", err)
	}

	if _, err := store.Token("session-1", "DNI", "87654321X"); err == nil {
		t.Fatal("Token returned no error against a corrupted session file, want a fail-closed error")
	}
}
