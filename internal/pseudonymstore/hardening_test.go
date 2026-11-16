package pseudonymstore_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

var errDisk = errors.New("fsync failed")

func writeV1(t *testing.T, dir string) string {
	t.Helper()
	legacy := filepath.Join(dir, "session-1.json")
	v1 := `{"mapping":{"DNI:12345678Z":"[DNI-001]"},"reverse":{"[DNI-001]":"12345678Z"},"counters":{"DNI":1}}`
	if err := os.WriteFile(legacy, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	return legacy
}

// TestFileStore_Migration_IsDurableBeforeThePlaintextGoes proves the v1
// file is removed only after the encrypted file's data and its directory
// entry reached stable storage: a failed fsync of either keeps the v1
// file and fails closed.
func TestFileStore_Migration_IsDurableBeforeThePlaintextGoes(t *testing.T) {
	for name, fail := range map[string][2]error{
		"file fsync fails":      {errDisk, nil},
		"directory fsync fails": {nil, errDisk},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			legacy := writeV1(t, dir)
			pseudonymstore.FailSync(t, fail[0], fail[1])

			_, _, err := newStore(t, dir, newFakeKeyring()).Original("session-1", "[DNI-001]")

			if !errors.Is(err, errDisk) {
				t.Fatalf("err = %v, want the fsync failure", err)
			}
			if !exists(t, legacy) {
				t.Fatal("the v1 file was removed although the encrypted copy was not durable")
			}
		})
	}
}

// TestFileStore_HostFDBelowThree_IsInvalid proves a host cannot hand veil
// stdin, stdout or stderr as the key descriptor: fd 0 would consume the
// hook event as the key.
func TestFileStore_HostFDBelowThree_IsInvalid(t *testing.T) {
	for _, fd := range []string{"0", "1", "2", "-1"} {
		t.Run(fd, func(t *testing.T) {
			keys := &pseudonymstore.KeyChain{FD: fd, Keyring: newFakeKeyring()}
			_, err := pseudonymstore.NewFileStore(t.TempDir(), keys).Token("session-1", "DNI", "12345678Z")
			wantErr(t, err, pseudonymstore.ErrKeyInvalid)
		})
	}
}

// TestFileStore_StaleTmp_IsNeverFollowedOrKept proves a leftover temp file
// (a symlink planted in a shared directory, or a 0644 file) is neither
// written through nor kept with its mode.
func TestFileStore_StaleTmp_IsNeverFollowedOrKept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and POSIX modes")
	}
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "session-1.age.tmp")); err != nil {
			t.Fatal(err)
		}

		mintOne(t, newStore(t, dir, newFakeKeyring()))

		if raw, _ := os.ReadFile(target); string(raw) != "untouched" {
			t.Fatalf("the symlink target was written: %q", raw)
		}
		info, err := os.Lstat(filepath.Join(dir, "session-1.age"))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("session file is not a regular file: %v %v", info, err)
		}
	})
	t.Run("0644 file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "session-1.age.tmp"), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}

		mintOne(t, newStore(t, dir, newFakeKeyring()))

		info, err := os.Stat(filepath.Join(dir, "session-1.age"))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("session file mode = %o, want 0600", perm)
		}
	})
}

// TestFileStore_ExistingSessionsDir_IsTightenedTo0700 proves a sessions
// directory created by someone else's umask (or a shared fallback) is
// made private before veil writes into it.
func TestFileStore_ExistingSessionsDir_IsTightenedTo0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	for _, op := range []string{"token", "reveal", "forget"} {
		t.Run(op, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "sessions")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			store := newStore(t, dir, newFakeKeyring())
			mintOne(t, store)
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}

			var err error
			switch op {
			case "token":
				_, err = store.Token("session-1", "DNI", "87654321X")
			case "reveal":
				_, err = store.Reveal("session-1")
			case "forget":
				err = store.Forget("session-1")
			}
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o700 {
				t.Fatalf("sessions dir mode = %o, want 0700", perm)
			}
		})
	}
}

// TestFileStore_Forget_RemovesV1TmpLeftover proves forget also removes an
// interrupted v1 write (<session>.json.tmp), which holds plaintext.
func TestFileStore_Forget_RemovesV1TmpLeftover(t *testing.T) {
	dir := t.TempDir()
	leftover := filepath.Join(dir, "session-1.json.tmp")
	if err := os.WriteFile(leftover, []byte(`{"reverse":{"[DNI-001]":"12345678Z"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := newStore(t, dir, newFakeKeyring()).Forget("session-1"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if exists(t, leftover) {
		t.Fatal("the v1 temp file (plaintext) survived Forget")
	}
}
