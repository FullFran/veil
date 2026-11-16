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

	got, err := clockAt(t, dir, kr, t0.Add(ttl+time.Hour)).Sweep(ttl, 0)
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}

	if !reflect.DeepEqual(got.Forgotten, []string{"old"}) || len(got.Skipped) != 0 {
		t.Fatalf("Sweep = %+v, want forgotten [old], nothing skipped", got)
	}
	if left := sessionFiles(t, dir, "old"); !reflect.DeepEqual(left, []string{"old.ctr"}) {
		t.Fatalf("expired session left %v behind, want only its counters", left)
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

	got, err := clockAt(t, dir, kr, t0.Add(ttl+time.Hour)).Sweep(ttl, 0)
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

	got, err := clockAt(t, dir, newFakeKeyring(), t0.Add(2*ttl)).Sweep(ttl, 0)
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
	got, err := clockAt(t, dir, kr, t0.Add(2*ttl)).Sweep(ttl, 0)
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
	got, err := clockAt(t, filepath.Join(t.TempDir(), "absent"), newFakeKeyring(), t0).Sweep(ttl, 0)
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

	child := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLock$") // #nosec G702 -- re-runs this test binary as the lock-holding child
	child.Env = append(os.Environ(), "VEIL_TEST_HOLD_LOCK="+filepath.Join(dir, "session-1.json.lock"))
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() }) // no-ops if the test already reaped it
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "held\n" {
		t.Fatalf("child said %q, want held", line)
	}

	_, err = store.Token("session-1", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrLocked)
	wantErr(t, store.Forget("session-1"), pseudonymstore.ErrLocked)

	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait() // killed on purpose, so Wait reports the signal

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

// TestRemovedSession_NeverReusesATokenNumber: the host's history of a
// resumed session still holds the old markers, so a session that was
// swept or forgotten and is then resumed must never mint an old marker
// for a new value, and rehydrating an old marker must never give the new
// value (it would write the wrong person's data to disk).
func TestRemovedSession_NeverReusesATokenNumber(t *testing.T) {
	remove := map[string]func(t *testing.T, dir string, kr *fakeKeyring){
		"sweep": func(t *testing.T, dir string, kr *fakeKeyring) {
			got, err := clockAt(t, dir, kr, t0.Add(2*ttl)).Sweep(ttl, 0)
			if err != nil || len(got.Forgotten) != 1 {
				t.Fatalf("Sweep = (%+v, %v), want s forgotten", got, err)
			}
		},
		"forget": func(t *testing.T, dir string, kr *fakeKeyring) {
			if err := newStore(t, dir, kr).Forget("s"); err != nil {
				t.Fatal(err)
			}
		},
		"forget without the key": func(t *testing.T, dir string, kr *fakeKeyring) {
			if err := newStore(t, dir, newFakeKeyring()).Forget("s"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, removeSession := range remove {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			kr := newFakeKeyring()
			if tok := mint(t, clockAt(t, dir, kr, t0), "s", "DNI", "12345678A"); tok != "[DNI-001]" {
				t.Fatalf("first token = %s, want [DNI-001]", tok)
			}

			removeSession(t, dir, kr)

			resumed := clockAt(t, dir, kr, t0.Add(3*ttl))
			if tok := mint(t, resumed, "s", "DNI", "87654321B"); tok == "[DNI-001]" {
				t.Fatalf("value B got %s, the marker value A had before removal", tok)
			}
			if original, ok, err := resumed.Original("s", "[DNI-001]"); err != nil || (ok && original == "87654321B") {
				t.Fatalf("Original([DNI-001]) = (%q, %v, %v), must never be value B", original, ok, err)
			}
		})
	}
}

// TestRemovedSession_KeepsOnlyCounters: what survives removal holds no
// value, is no session to find or reveal, and is not swept as one.
func TestRemovedSession_KeepsOnlyCounters(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "s", "DNI", "12345678Z")
	mint(t, clockAt(t, dir, kr, t0), "s", "EMAIL", "ana@example.com")
	if err := newStore(t, dir, kr).Forget("s"); err != nil {
		t.Fatal(err)
	}

	left := sessionFiles(t, dir, "s")
	if !reflect.DeepEqual(left, []string{"s.ctr"}) {
		t.Fatalf("files left = %v, want only s.ctr", left)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "s.ctr"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"12345678Z", "ana@example.com", "[DNI-001]"} {
		if strings.Contains(string(raw), value) {
			t.Fatalf("s.ctr %q holds %q", raw, value)
		}
	}
	if got, err := newStore(t, dir, kr).Find([]string{"12345678Z"}); err != nil || len(got) != 0 {
		t.Fatalf("Find after forget = (%v, %v), want nothing", got, err)
	}
	if got, err := clockAt(t, dir, kr, t0.Add(100*ttl)).Sweep(ttl, 0); err != nil || len(got.Forgotten) != 0 {
		t.Fatalf("Sweep of a counters file = (%+v, %v), want nothing forgotten", got, err)
	}
}

// TestRemoval_UnreadableCounters_RetiresTheSession: a session written
// before counters files existed, removed without a key that opens it, has
// lost its numbering. Removal still happens (erasure is never blocked),
// but the session id is retired: minting for it fails closed instead of
// starting again at -001.
func TestRemoval_UnreadableCounters_RetiresTheSession(t *testing.T) {
	remove := map[string]func(t *testing.T, dir string){
		"forget without the key": func(t *testing.T, dir string) {
			if err := newStore(t, dir, newFakeKeyring()).Forget("p1"); err != nil {
				t.Fatal(err)
			}
		},
		"sweep with a wrong key": func(t *testing.T, dir string) {
			wrong := newFakeKeyring()
			wrong.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = newIdentity(t).String()
			got, err := clockAt(t, dir, wrong, t0.Add(2*ttl)).Sweep(ttl, 0)
			if err != nil || !reflect.DeepEqual(got.Forgotten, []string{"p1"}) {
				t.Fatalf("Sweep = (%+v, %v), want p1 forgotten", got, err)
			}
		},
	}
	for name, removeSession := range remove {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			kr := newFakeKeyring()
			mint(t, clockAt(t, dir, kr, t0), "p1", "DNI", "12345678Z")
			mint(t, clockAt(t, dir, kr, t0), "p1", "DNI", "87654321X")
			if err := os.Remove(filepath.Join(dir, "p1.ctr")); err != nil { // as written before counters files
				t.Fatal(err)
			}

			removeSession(t, dir)

			if exists(t, filepath.Join(dir, "p1.age")) {
				t.Fatal("removal was blocked")
			}
			raw, err := os.ReadFile(filepath.Join(dir, "p1.ctr"))
			if err != nil || strings.Contains(string(raw), "12345678Z") {
				t.Fatalf("p1.ctr = (%q, %v), want a tombstone with no value", raw, err)
			}
			token, err := clockAt(t, dir, kr, t0.Add(3*ttl)).Token("p1", "DNI", "11111111H")
			wantErr(t, err, pseudonymstore.ErrSessionRetired)
			if token != "" {
				t.Fatalf("retired session minted %q", token)
			}
		})
	}
}

// TestRemoval_IsDurable: removal syncs the directory, so a power loss
// cannot bring a deleted session file back.
func TestRemoval_IsDurable(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "forgotten", "DNI", "12345678Z")
	mint(t, clockAt(t, dir, kr, t0), "swept", "DNI", "12345678Z")
	pseudonymstore.FailSync(t, nil, errDisk)

	wantErr(t, newStore(t, dir, kr).Forget("forgotten"), errDisk)
	got, err := clockAt(t, dir, kr, t0.Add(2*ttl)).Sweep(ttl, 0)
	wantErr(t, err, errDisk)
	if !reflect.DeepEqual(got.Failed, []string{"swept"}) {
		t.Fatalf("Sweep with a failing dir sync = %+v, want swept failed", got)
	}
}

// TestSweep_OnePoisonedSession_DoesNotBlockTheRest: a session that cannot
// be locked (its lock path is a symlink) is reported failed, and the
// sweep still removes the others.
func TestSweep_OnePoisonedSession_DoesNotBlockTheRest(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "a1", "DNI", "12345678Z")
	mint(t, clockAt(t, dir, kr, t0), "b2", "DNI", "12345678Z")
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), filepath.Join(dir, "a1.json.lock")); err != nil {
		t.Fatal(err)
	}

	got, err := clockAt(t, dir, kr, t0.Add(2*ttl)).Sweep(ttl, 0)

	if err == nil {
		t.Fatal("Sweep hid a failed session")
	}
	if !reflect.DeepEqual(got.Failed, []string{"a1"}) || !reflect.DeepEqual(got.Forgotten, []string{"b2"}) {
		t.Fatalf("Sweep = %+v, want a1 failed and b2 forgotten", got)
	}
}

// TestSweep_SessionUsedMeanwhile_IsKeptAndNotReported: the re-check under
// the lock keeps a session another process used after the first check.
func TestSweep_SessionUsedMeanwhile_IsKeptAndNotReported(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	mint(t, clockAt(t, dir, kr, t0), "s", "DNI", "12345678Z")
	now := t0.Add(2 * ttl)
	pseudonymstore.OnSweepLocked(t, func(id string) {
		if err := os.Chtimes(filepath.Join(dir, id+".age"), now, now); err != nil {
			t.Errorf("Chtimes: %v", err)
		}
	})

	got, err := clockAt(t, dir, kr, now).Sweep(ttl, 0)

	if err != nil || len(got.Forgotten) != 0 || !exists(t, filepath.Join(dir, "s.age")) {
		t.Fatalf("Sweep = (%+v, %v), s present = %v; want s kept and not reported", got, err, exists(t, filepath.Join(dir, "s.age")))
	}
}

// TestSweep_Limit_BoundsOneRun: a bounded sweep removes at most limit
// sessions per run; the next run carries on.
func TestSweep_Limit_BoundsOneRun(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	for _, id := range []string{"a", "b", "c"} {
		mint(t, clockAt(t, dir, kr, t0), id, "DNI", "12345678Z")
	}
	later := clockAt(t, dir, kr, t0.Add(2*ttl))

	first, err := later.Sweep(ttl, 2)
	if err != nil || len(first.Forgotten) != 2 {
		t.Fatalf("first Sweep = (%+v, %v), want 2 forgotten", first, err)
	}
	second, err := later.Sweep(ttl, 2)
	if err != nil || len(second.Forgotten) != 1 {
		t.Fatalf("second Sweep = (%+v, %v), want the last one forgotten", second, err)
	}
}

// TestFind_IsReadOnly: find never migrates or rewrites what it reads.
func TestFind_IsReadOnly(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	legacy := writeV1(t, dir)

	got, err := newStore(t, dir, kr).Find([]string{"12345678Z"})

	want := []pseudonymstore.Holding{{Session: "session-1", Categories: []string{"DNI"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Find = (%+v, %v), want %+v", got, err, want)
	}
	if !exists(t, legacy) || exists(t, filepath.Join(dir, "session-1.age")) || kr.sets != 0 {
		t.Fatal("Find migrated a v1 session or generated a key; it must only read")
	}
}
