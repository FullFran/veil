package pseudonymstore_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

var errCrash = errors.New("crash")

// writeLegacy builds the files a veil before #26 left for stem: it mints
// values as session stem with the current store, then moves the files to
// their legacy names (<dir>/<stem>.age and .ctr), which hold exactly that
// format.
func writeLegacy(t *testing.T, dir string, kr *fakeKeyring, stem string, values ...string) []string {
	t.Helper()
	store := newStore(t, dir, kr)
	var tokens []string
	for _, v := range values {
		tokens = append(tokens, mint(t, store, stem, "DNI", v))
	}
	for _, suffix := range []string{".age", ".ctr"} {
		if err := os.Rename(pseudonymstore.SessionPath(dir, stem)+suffix, filepath.Join(dir, stem+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	return tokens
}

func legacyFile(dir, stem, suffix string) string { return filepath.Join(dir, stem+suffix) }

// TestMigration_UnambiguousLegacy_KeepsItsMarkers proves a legacy stem
// only one session id can have produced (no "_", not unknown-session) is
// that session's: its markers still rehydrate, numbering carries on, and
// its files are moved, not copied.
func TestMigration_UnambiguousLegacy_KeepsItsMarkers(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	tokens := writeLegacy(t, dir, kr, "5b7a6e2a-6a2e-4b7a", "12345678Z")
	store := newStore(t, dir, kr)

	got, ok, err := store.Original("5b7a6e2a-6a2e-4b7a", tokens[0])
	if err != nil || !ok || got != "12345678Z" {
		t.Fatalf("Original = %q, %v, %v; want the legacy value", got, ok, err)
	}
	if tok := mint(t, store, "5b7a6e2a-6a2e-4b7a", "DNI", "87654321X"); tok != "[DNI-002]" {
		t.Fatalf("next marker = %s, want [DNI-002]", tok)
	}
	for _, suffix := range []string{".age", ".ctr"} {
		if exists(t, legacyFile(dir, "5b7a6e2a-6a2e-4b7a", suffix)) {
			t.Errorf("legacy %s file left behind", suffix)
		}
	}
}

// TestMigration_CrashBetweenRenames_IsFinishedByTheNextUse proves a
// migration cut short after any one rename leaves a state the next use
// completes, with no marker lost or reused.
func TestMigration_CrashBetweenRenames_IsFinishedByTheNextUse(t *testing.T) {
	for _, suffix := range []string{".ctr", ".age"} {
		t.Run(suffix, func(t *testing.T) {
			dir := t.TempDir()
			kr := newFakeKeyring()
			tokens := writeLegacy(t, dir, kr, "s1", "12345678Z")
			recover := pseudonymstore.CrashMigrationAfter(t, suffix, errCrash)

			if _, _, err := newStore(t, dir, kr).Original("s1", tokens[0]); !errors.Is(err, errCrash) {
				t.Fatalf("err = %v, want the crash", err)
			}
			recover()

			store := newStore(t, dir, kr)
			if got, ok, err := store.Original("s1", tokens[0]); err != nil || !ok || got != "12345678Z" {
				t.Fatalf("after the crash, Original = %q, %v, %v", got, ok, err)
			}
			if tok := mint(t, store, "s1", "DNI", "87654321X"); tok != "[DNI-002]" {
				t.Fatalf("next marker = %s, want [DNI-002]", tok)
			}
		})
	}
}

// TestMigration_FailedDirSync_FailsClosed proves a migration whose
// directory entries cannot be made durable reports it.
func TestMigration_FailedDirSync_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	tokens := writeLegacy(t, dir, kr, "s1", "12345678Z")
	pseudonymstore.FailSync(t, nil, errDisk)

	if _, _, err := newStore(t, dir, kr).Original("s1", tokens[0]); !errors.Is(err, errDisk) {
		t.Fatalf("err = %v, want the fsync failure", err)
	}
}

// TestMigration_LegacyAndCurrentBothPresent_FailsClosed proves a legacy
// file is never merged into, nor overwrites, a current one of the same
// session: both stay and the session fails closed.
func TestMigration_LegacyAndCurrentBothPresent_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	writeLegacy(t, dir, kr, "s1", "12345678Z")
	mint(t, newStore(t, dir, kr), "other", "DNI", "1")
	// A current file for s1 that is not the legacy one.
	for _, suffix := range []string{".age", ".ctr"} {
		raw, err := os.ReadFile(pseudonymstore.SessionPath(dir, "other") + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pseudonymstore.SessionPath(dir, "s1")+suffix, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_, err := newStore(t, dir, kr).Token("s1", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrCorrupt)
	if !exists(t, legacyFile(dir, "s1", ".age")) || !exists(t, pseudonymstore.SessionPath(dir, "s1")+".age") {
		t.Fatal("a conflicting file was removed")
	}
}

// TestMigration_AmbiguousLegacy_IsNeverMerged proves a legacy stem
// several ids could have produced (a_b: a/b, a\b, a..b or a_b) is never
// read for any of them: none rehydrates its markers, each counts on from
// its counters (so no marker number repeats one the host history may
// hold), the stem stays findable by its own name and only ForgetLegacy
// erases it, keeping its counters.
func TestMigration_AmbiguousLegacy_IsNeverMerged(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	tokens := writeLegacy(t, dir, kr, "a_b", "12345678Z")
	store := newStore(t, dir, kr)

	for _, id := range collidingIDs {
		if _, ok, err := store.Original(id, tokens[0]); err != nil || ok {
			t.Errorf("Original(%q) found the legacy marker (err %v)", id, err)
		}
		if tok := mint(t, store, id, "DNI", "87654321X"); tok != "[DNI-002]" {
			t.Errorf("Token(%q) = %s, want [DNI-002] (seeded counters)", id, tok)
		}
	}
	if err := store.Forget("a/b"); err != nil {
		t.Fatal(err)
	}
	if !exists(t, legacyFile(dir, "a_b", ".age")) {
		t.Fatal("Forget(a/b) removed the shared legacy store")
	}

	holdings, err := store.Find([]string{"12345678Z"})
	if err != nil {
		t.Fatal(err)
	}
	want := []pseudonymstore.Holding{{LegacyStem: "a_b", Categories: []string{"DNI"}}}
	if !reflect.DeepEqual(holdings, want) {
		t.Fatalf("Find = %+v, want %+v", holdings, want)
	}

	if err := store.ForgetLegacy("a_b"); err != nil {
		t.Fatal(err)
	}
	if exists(t, legacyFile(dir, "a_b", ".age")) || !exists(t, legacyFile(dir, "a_b", ".ctr")) {
		t.Fatal("ForgetLegacy must remove the store and keep its counters")
	}
}

// TestMigration_AmbiguousLegacyWithoutCounters_SeedsFromItsMapping covers
// a legacy store written before counters files: its counters come from
// the mapping, with the key.
func TestMigration_AmbiguousLegacyWithoutCounters_SeedsFromItsMapping(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	writeLegacy(t, dir, kr, "unknown-session", "12345678Z", "87654321X")
	if err := os.Remove(legacyFile(dir, "unknown-session", ".ctr")); err != nil {
		t.Fatal(err)
	}

	if tok := mint(t, newStore(t, dir, kr), "unknown-session", "DNI", "11111111H"); tok != "[DNI-003]" {
		t.Fatalf("Token = %s, want [DNI-003]", tok)
	}
}

// TestMigration_AmbiguousLegacyUnreadable_FailsClosed proves a seed that
// cannot be read (no key opens the legacy mapping) never lets the
// session mint from zero.
func TestMigration_AmbiguousLegacyUnreadable_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir, newFakeKeyring(), "a_b", "12345678Z")
	if err := os.Remove(legacyFile(dir, "a_b", ".ctr")); err != nil {
		t.Fatal(err)
	}
	other := newFakeKeyring()
	mint(t, newStore(t, t.TempDir(), other), "x", "DNI", "1") // a key that does not open a_b

	_, err := newStore(t, dir, other).Token("a/b", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrKeyInvalid)
	if exists(t, pseudonymstore.SessionPath(dir, "a/b")+".ctr") {
		t.Fatal("a failed seed wrote counters")
	}
}

// TestMigration_RetiredAmbiguousLegacy_RetiresTheSession proves a legacy
// tombstone retires every id that could have used it.
func TestMigration_RetiredAmbiguousLegacy_RetiresTheSession(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	writeLegacy(t, dir, kr, "a_b", "12345678Z")
	if err := os.WriteFile(legacyFile(dir, "a_b", ".ctr"), []byte(`{"version":1,"retired":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := newStore(t, dir, kr).Token("a/b", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrSessionRetired)
}

// TestReports_NameTheRealSessionID proves find and sweep report the
// session id the host used, never a file stem, including for an id too
// long for a plain stem.
func TestReports_NameTheRealSessionID(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	long := strings.Repeat("x", 200)
	longToo := long + "y" // same first 60 bytes, another session
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, id := range []string{"a/b", long, longToo} {
		mint(t, clockAt(t, dir, kr, t0), id, "DNI", "12345678Z")
	}
	if tok := mint(t, clockAt(t, dir, kr, t0), longToo, "DNI", "87654321X"); tok != "[DNI-002]" {
		t.Fatalf("long ids share counters: %s", tok)
	}

	holdings, err := newStore(t, dir, kr).Find([]string{"12345678Z"})
	if err != nil {
		t.Fatal(err)
	}
	var sessions []string
	for _, h := range holdings {
		sessions = append(sessions, h.Session)
	}
	if want := []string{"a/b", long, longToo}; !reflect.DeepEqual(sessions, want) {
		t.Fatalf("Find sessions = %q, want %q", sessions, want)
	}

	got, err := clockAt(t, dir, kr, t0.Add(48*time.Hour)).Sweep(time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a/b", long, longToo}; !reflect.DeepEqual(got.Forgotten, want) {
		t.Fatalf("Sweep forgot %q, want %q", got.Forgotten, want)
	}
	if !exists(t, pseudonymstore.SessionPath(dir, long)+".id") {
		t.Fatal("a hashed stem lost the file that names its session")
	}
	if name := filepath.Base(pseudonymstore.SessionPath(dir, long)); len(name)+len(".json.tmp") > 255 {
		t.Fatalf("stem of %d bytes exceeds NAME_MAX with its suffix", len(name))
	}
}

// TestSweep_AmbiguousLegacy_IsReportedByStem proves a legacy stem with no
// knowable session id is swept and reported apart from sessions.
func TestSweep_AmbiguousLegacy_IsReportedByStem(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	writeLegacy(t, dir, kr, "a_b", "12345678Z")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(legacyFile(dir, "a_b", ".age"), old, old); err != nil {
		t.Fatal(err)
	}

	got, err := newStore(t, dir, kr).Sweep(time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Forgotten) != 0 || !reflect.DeepEqual(got.LegacyStems.Forgotten, []string{"a_b"}) {
		t.Fatalf("Sweep = %+v, want a_b under legacy_stems only", got)
	}
	if !exists(t, legacyFile(dir, "a_b", ".ctr")) {
		t.Fatal("sweep removed the legacy counters")
	}
}

// TestForgetLegacy_RefusesAnythingButAPlainName keeps ForgetLegacy inside
// the store directory.
func TestForgetLegacy_RefusesAnythingButAPlainName(t *testing.T) {
	store := newStore(t, t.TempDir(), newFakeKeyring())
	for _, stem := range []string{"", ".", "..", "../x", `a\b`, "a/b"} {
		if err := store.ForgetLegacy(stem); !errors.Is(err, pseudonymstore.ErrLegacyStemInvalid) {
			t.Errorf("ForgetLegacy(%q) = %v, want ErrLegacyStemInvalid", stem, err)
		}
	}
}

// TestMigration_UnambiguousLegacy_KeepsItsWrittenForms proves the
// migration carries each marker's first written form (#27) over with the
// file: after the move the marker still rehydrates to "612 345 678", not
// to its canonical key, and a later form of the same key keeps it.
func TestMigration_UnambiguousLegacy_KeepsItsWrittenForms(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	const session = "5b7a6e2a-6a2e-4b7a"
	token, err := newStore(t, dir, kr).TokenFor(session, "TEL", "+34612345678", "612 345 678")
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".age", ".ctr"} {
		if err := os.Rename(pseudonymstore.SessionPath(dir, session)+suffix, legacyFile(dir, session, suffix)); err != nil {
			t.Fatal(err)
		}
	}
	store := newStore(t, dir, kr)

	again, err := store.TokenFor(session, "TEL", "+34612345678", "+34 612 345 678")
	if err != nil || again != token {
		t.Fatalf("TokenFor after migration = %q, %v; want %s", again, err, token)
	}
	got, ok, err := store.Original(session, token)
	if err != nil || !ok || got != "612 345 678" {
		t.Fatalf("Original = %q, %v, %v; want the first written form", got, ok, err)
	}
	if _, err := os.Stat(legacyFile(dir, session, ".age")); !os.IsNotExist(err) {
		t.Fatal("the legacy age file was not moved")
	}
}

// TestHashedStem_TamperedIDFile_FailsClosed proves the .id file of a
// hashed stem is checked on every opening of the session, not only when
// it is first written: one naming another id fails Token, Original and
// Reveal closed with ErrCorrupt.
func TestHashedStem_TamperedIDFile_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	long := strings.Repeat("x", 200)
	token := mint(t, newStore(t, dir, kr), long, "DNI", "12345678Z")
	if err := os.WriteFile(pseudonymstore.SessionPath(dir, long)+".id", []byte(long+"y"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newStore(t, dir, kr)

	if _, err := store.Token(long, "DNI", "12345678Z"); !errors.Is(err, pseudonymstore.ErrCorrupt) {
		t.Errorf("Token = %v, want ErrCorrupt", err)
	}
	if _, _, err := store.Original(long, token); !errors.Is(err, pseudonymstore.ErrCorrupt) {
		t.Errorf("Original = %v, want ErrCorrupt", err)
	}
	if _, err := store.Reveal(long); !errors.Is(err, pseudonymstore.ErrCorrupt) {
		t.Errorf("Reveal = %v, want ErrCorrupt", err)
	}
}

// TestHashedStem_MissingIDFile_IsRestored proves a deleted .id file is
// written again on the next use: the stem is the SHA-256 of the id the
// caller names, so that id is provably the session's (barring a
// collision), and reports name it again.
func TestHashedStem_MissingIDFile_IsRestored(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	long := strings.Repeat("x", 200)
	token := mint(t, newStore(t, dir, kr), long, "DNI", "12345678Z")
	idFile := pseudonymstore.SessionPath(dir, long) + ".id"
	if err := os.Remove(idFile); err != nil {
		t.Fatal(err)
	}

	got, ok, err := newStore(t, dir, kr).Original(long, token)
	if err != nil || !ok || got != "12345678Z" {
		t.Fatalf("Original = %q, %v, %v", got, ok, err)
	}
	if raw, err := os.ReadFile(idFile); err != nil || string(raw) != long {
		t.Fatalf(".id file = %q, %v; want the session id", raw, err)
	}
}

// TestSweep_UnnameableEntry_IsReportedAsFailedAndTheRestIsSwept proves one
// file in ids/ that names no session (bad base32, or a hashed stem whose
// .id file is gone) does not stop retention: it is reported under failed
// by its file stem, the error is ErrCorrupt, and every other expired
// session is still removed. Find, which must not answer partially, fails
// closed instead.
func TestSweep_UnnameableEntry_IsReportedAsFailedAndTheRestIsSwept(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	long := strings.Repeat("x", 200)
	for _, id := range []string{"sess-1", long} {
		mint(t, clockAt(t, dir, kr, t0), id, "DNI", "12345678Z")
	}
	stem := filepath.Base(pseudonymstore.SessionPath(dir, long))
	if err := os.Remove(pseudonymstore.SessionPath(dir, long) + ".id"); err != nil {
		t.Fatal(err)
	}

	got, err := clockAt(t, dir, kr, t0.Add(48*time.Hour)).Sweep(time.Hour, 0)

	if !errors.Is(err, pseudonymstore.ErrCorrupt) {
		t.Fatalf("Sweep err = %v, want ErrCorrupt", err)
	}
	if !reflect.DeepEqual(got.Forgotten, []string{"sess-1"}) || !reflect.DeepEqual(got.Failed, []string{"ids/" + stem}) {
		t.Fatalf("Sweep = %+v, want sess-1 forgotten and ids/%s failed", got, stem)
	}
	if _, err := newStore(t, dir, kr).Find([]string{"12345678Z"}); !errors.Is(err, pseudonymstore.ErrCorrupt) {
		t.Fatalf("Find = %v, want ErrCorrupt", err)
	}
}
