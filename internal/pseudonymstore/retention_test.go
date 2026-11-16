package pseudonymstore_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

const ttl = 30 * 24 * time.Hour

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// clockAt returns a store over dir, sharing keyring kr, whose clock reads at.
func clockAt(t *testing.T, dir string, kr pseudonymstore.Keyring, at time.Time) *pseudonymstore.FileStore {
	t.Helper()
	return newStore(t, dir, kr).WithClock(func() time.Time { return at })
}

func mint(t *testing.T, store *pseudonymstore.FileStore, session, category, value string) string {
	t.Helper()
	token, err := store.Token(session, category, value)
	if err != nil {
		t.Fatalf("Token(%s) failed: %v", session, err)
	}
	return token
}

func sessionFiles(t *testing.T, dir, session string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), session+".") {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestSweep_RemovesExpiredSession_KeepsUnexpiredOne(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "old", "DNI", "12345678Z")
	mint(t, clockAt(t, dir, kr, t0.Add(10*24*time.Hour)), "recent", "DNI", "87654321X")

	got, err := clockAt(t, dir, kr, t0.Add(ttl+time.Hour)).Sweep(ttl)
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}

	if !reflect.DeepEqual(got.Forgotten, []string{"old"}) || len(got.Skipped) != 0 {
		t.Fatalf("Sweep = %+v, want forgotten [old], nothing skipped", got)
	}
	if left := sessionFiles(t, dir, "old"); len(left) != 0 {
		t.Fatalf("expired session left %v behind", left)
	}
	if len(sessionFiles(t, dir, "recent")) == 0 {
		t.Fatal("unexpired session was removed")
	}
}

// TestSweep_ExpiryCountsFromLastUse: a lookup of an existing token is use,
// so a long, active session is never swept mid-use.
func TestSweep_ExpiryCountsFromLastUse(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "looked-up", "DNI", "12345678Z")
	mint(t, clockAt(t, dir, kr, t0), "rehydrated", "DNI", "12345678Z")
	later := t0.Add(ttl - time.Hour)
	mint(t, clockAt(t, dir, kr, later), "looked-up", "DNI", "12345678Z")
	if _, _, err := clockAt(t, dir, kr, later).Original("rehydrated", "[DNI-001]"); err != nil {
		t.Fatal(err)
	}

	got, err := clockAt(t, dir, kr, t0.Add(ttl+time.Hour)).Sweep(ttl)
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}
	if len(got.Forgotten) != 0 {
		t.Fatalf("Sweep forgot %v, want nothing: both sessions were used recently", got.Forgotten)
	}
}

// TestSweep_NeedsNoKey: expiry is decided without decrypting, so a lost
// key never blocks deletion.
func TestSweep_NeedsNoKey(t *testing.T) {
	dir := t.TempDir()
	mint(t, clockAt(t, dir, newFakeKeyring(), t0), "old", "DNI", "12345678Z")

	got, err := clockAt(t, dir, newFakeKeyring(), t0.Add(2*ttl)).Sweep(ttl)
	if err != nil || !reflect.DeepEqual(got.Forgotten, []string{"old"}) {
		t.Fatalf("Sweep without the key = (%+v, %v), want old forgotten", got, err)
	}
}

func TestSweep_SkipsASessionAnotherProcessHoldsLocked(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "busy", "DNI", "12345678Z")
	pseudonymstore.HoldLock(t, filepath.Join(dir, "busy.json.lock"))

	start := time.Now()
	got, err := clockAt(t, dir, kr, t0.Add(2*ttl)).Sweep(ttl)
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}
	if !reflect.DeepEqual(got.Skipped, []string{"busy"}) || len(got.Forgotten) != 0 {
		t.Fatalf("Sweep = %+v, want busy skipped and nothing forgotten", got)
	}
	if !exists(t, filepath.Join(dir, "busy.age")) {
		t.Fatal("Sweep deleted a locked session")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Sweep waited %v on a held lock, want no wait", time.Since(start))
	}
}

func TestSweep_MissingDir_IsEmpty(t *testing.T) {
	got, err := clockAt(t, filepath.Join(t.TempDir(), "absent"), newFakeKeyring(), t0).Sweep(ttl)
	if err != nil || len(got.Forgotten)+len(got.Skipped) != 0 {
		t.Fatalf("Sweep(missing dir) = (%+v, %v), want empty", got, err)
	}
}

func TestFind_ListsSessionsAndCategoriesHoldingTheValue(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())
	mint(t, store, "a", "DNI", "12345678Z")
	mint(t, store, "a", "EMAIL", "ana@example.com")
	mint(t, store, "b", "TEL", "600123456")
	mint(t, store, "c", "NOMBRE", "12345678Z")

	got, err := store.Find([]string{"12345678Z"})
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	want := []pseudonymstore.Holding{
		{Session: "a", Categories: []string{"DNI"}},
		{Session: "c", Categories: []string{"NOMBRE"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Find = %+v, want %+v", got, want)
	}
	if fmt.Sprint(got) == "" || strings.Contains(fmt.Sprintf("%+v", got), "12345678Z") {
		t.Fatalf("Find answer %+v carries a value", got)
	}
}

func TestFind_NoMatch_IsEmptyNotNil(t *testing.T) {
	store := newStore(t, t.TempDir(), newFakeKeyring())
	mint(t, store, "a", "DNI", "12345678Z")

	got, err := store.Find([]string{"87654321X"})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("Find = (%#v, %v), want an empty list", got, err)
	}
}

func TestFind_WrongOrMissingKey_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	owner := newFakeKeyring()
	mint(t, newStore(t, dir, owner), "a", "DNI", "12345678Z")

	_, err := newStore(t, dir, newFakeKeyring()).Find([]string{"12345678Z"})
	wantErr(t, err, pseudonymstore.ErrKeyMissing)

	wrong := newFakeKeyring()
	wrong.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = newIdentity(t).String()
	got, err := newStore(t, dir, wrong).Find([]string{"12345678Z"})
	wantErr(t, err, pseudonymstore.ErrKeyInvalid)
	if got != nil {
		t.Fatalf("Find returned %v alongside an error, want nothing", got)
	}
}

// TestLock_StaleLockFile_IsRecovered: a lock file left by a crashed
// process (no holder) no longer blocks the session or forget.
func TestLock_StaleLockFile_IsRecovered(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())
	mintOne(t, store)
	if err := os.WriteFile(filepath.Join(dir, "session-1.json.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Token("session-1", "DNI", "87654321X"); err != nil {
		t.Fatalf("Token with a stale lock file = %v, want success", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session-1.json.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Forget("session-1"); err != nil {
		t.Fatalf("Forget with a stale lock file = %v, want success", err)
	}
}

// TestLock_HolderKilled_IsReleasedAndNeverShared runs a child process
// that takes the session lock, proves the lock excludes this process
// while the child lives, then kills the child with SIGKILL (no cleanup
// runs) and proves the session recovers.
func TestLock_HolderKilled_IsReleasedAndNeverShared(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())
	mintOne(t, store)

	child := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLock$")
	child.Env = append(os.Environ(), "VEIL_TEST_HOLD_LOCK="+filepath.Join(dir, "session-1.json.lock"))
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "held\n" {
		t.Fatalf("child said %q, want held", line)
	}

	_, err = store.Token("session-1", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrLocked)
	wantErr(t, store.Forget("session-1"), pseudonymstore.ErrLocked)

	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.Wait()

	if token, err := store.Token("session-1", "DNI", "87654321X"); err != nil || token != "[DNI-002]" {
		t.Fatalf("Token after the holder died = (%q, %v), want ([DNI-002], nil)", token, err)
	}
}

// TestHelperHoldLock is the child of TestLock_HolderKilled: it holds the
// lock until it is killed. It does nothing in a normal test run.
func TestHelperHoldLock(t *testing.T) {
	path := os.Getenv("VEIL_TEST_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	pseudonymstore.HoldLock(t, path)
	fmt.Println("held")
	time.Sleep(time.Minute)
}
