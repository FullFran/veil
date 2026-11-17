package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"filippo.io/age"

	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

// TestMain swaps the OS keyring for an in-memory fake before any test
// runs, so the suite never reads or writes the real keyring, and clears
// the evidence variables a developer machine may set, so no test writes
// evidence into a real file or fails on an ambient revision (tests that
// need them use t.Setenv).
func TestMain(m *testing.M) {
	keyring = newFakeKeyring()
	os.Unsetenv(evidenceFileEnv)
	os.Unsetenv(catalogRevisionEnv)
	os.Exit(m.Run())
}

type fakeKeyring struct {
	mu      sync.Mutex
	secrets map[string]string
	err     error
}

func newFakeKeyring() *fakeKeyring { return &fakeKeyring{secrets: map[string]string{}} }

func (f *fakeKeyring) Get(service, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	s, ok := f.secrets[service+"/"+account]
	if !ok {
		return "", pseudonymstore.ErrKeyringNotFound
	}
	return s, nil
}

func (f *fakeKeyring) Set(service, account, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.secrets[service+"/"+account] = secret
	return nil
}

// useKeyring gives one test its own keyring and restores the shared fake.
func useKeyring(t *testing.T, kr pseudonymstore.Keyring) {
	t.Helper()
	previous := keyring
	keyring = kr
	t.Cleanup(func() { keyring = previous })
}

func sessionsDir() string {
	return filepath.Join(os.Getenv("XDG_STATE_HOME"), "veil", "sessions")
}

// sessionFile is the path of one of session's files (suffix ".age",
// ".ctr", ".lock"...).
func sessionFile(session, suffix string) string {
	return pseudonymstore.SessionPath(sessionsDir(), session) + suffix
}

// foreignSession writes sess-1 encrypted to a key no source will give.
func foreignSession(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other := newFakeKeyring()
	other.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = id.String()
	dir := sessionsDir()
	store := pseudonymstore.NewFileStore(dir, &pseudonymstore.KeyChain{Keyring: other, LockPath: filepath.Join(dir, "key.lock")})
	if _, err := store.Token("sess-1", "DNI", "12345678Z"); err != nil {
		t.Fatal(err)
	}
}

// TestRun_StoreFailures_ReportTheirCode covers each store failure the
// binary raises from a hook call: each fails closed with its own code.
func TestRun_StoreFailures_ReportTheirCode(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T)
		wantCode problem.Code
	}{
		{"store locked", func(t *testing.T) {
			if err := os.MkdirAll(filepath.Dir(sessionFile("sess-1", "")), 0o700); err != nil {
				t.Fatal(err)
			}
			holdLock(t, sessionFile("sess-1", ".lock"))
		}, problem.StoreLocked},
		{"key missing for an existing store", func(t *testing.T) {
			useKeyring(t, newFakeKeyring())
			foreignSession(t)
			useKeyring(t, newFakeKeyring())
		}, problem.StoreKeyMissing},
		{"wrong key", func(t *testing.T) {
			kr := newFakeKeyring()
			useKeyring(t, kr)
			foreignSession(t)
			id, _ := age.GenerateX25519Identity()
			kr.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = id.String()
		}, problem.StoreKeyInvalid},
		{"malformed systemd credential", func(t *testing.T) {
			creds := t.TempDir()
			if err := os.WriteFile(filepath.Join(creds, pseudonymstore.CredentialName), []byte("hunter2"), 0o400); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CREDENTIALS_DIRECTORY", creds)
		}, problem.StoreKeyInvalid},
		{"host fd not a descriptor", func(t *testing.T) { t.Setenv(pseudonymstore.KeyFDEnv, "x") }, problem.StoreKeyMissing},
		{"no keyring", func(t *testing.T) {
			useKeyring(t, &fakeKeyring{secrets: map[string]string{}, err: errors.New("no D-Bus session")})
		}, problem.StoreKeyringUnavailable},
		{"session retired by a keyless forget without counters", func(t *testing.T) {
			useKeyring(t, newFakeKeyring())
			foreignSession(t)
			if err := os.Remove(sessionFile("sess-1", ".ctr")); err != nil {
				t.Fatal(err)
			}
			if exit, _, stderr := storeCmd("forget", "sess-1"); exit != problem.ExitDecision {
				t.Fatalf("forget = (exit %d, %q), want 0", exit, stderr)
			}
		}, problem.SessionRetired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			tc.setup(t)
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{"opencode"}, strings.NewReader(dniTool), &stdout, &stderr)

			if exitCode != ocFailed {
				t.Fatalf("exitCode = %d, want %d", exitCode, ocFailed)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want nothing on a failure", stdout.String())
			}
			assertProblem(t, stderr.String(), tc.wantCode)
		})
	}
}

// holdLock holds the session lock at path for the rest of the test, as
// another veil process would: a flock on the lock file. A lock file
// without a holder is stale and veil takes it over.
func holdLock(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}
