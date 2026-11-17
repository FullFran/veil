package pseudonymstore_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"filippo.io/age"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

// mintOne writes one DNI token to session-1 and returns it.
func mintOne(t *testing.T, store *pseudonymstore.FileStore) string {
	t.Helper()
	token, err := store.Token("session-1", "DNI", "12345678Z")
	if err != nil {
		t.Fatalf("Token returned unexpected error: %v", err)
	}
	return token
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want one wrapping %v", err, want)
	}
}

// keyFD returns the number of a descriptor that reads content, as a host
// would pass it through VEIL_KEY_FD. The descriptor is a dup the store
// may close without touching the test's own pipe.
func keyFD(t *testing.T, content string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := w.WriteString(content); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatalf("Dup failed: %v", err)
	}
	return strconv.Itoa(fd)
}

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity failed: %v", err)
	}
	return id
}

func TestFileStore_WrongKey_FailsClosedWithKeyInvalid(t *testing.T) {
	dir := t.TempDir()
	mintOne(t, newStore(t, dir, newFakeKeyring()))

	other := newFakeKeyring()
	other.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = newIdentity(t).String()

	_, _, err := newStore(t, dir, other).Original("session-1", "[DNI-001]")
	wantErr(t, err, pseudonymstore.ErrKeyInvalid)
}

func TestFileStore_MissingKey_ForAnExistingStore_FailsClosedWithKeyMissing(t *testing.T) {
	dir := t.TempDir()
	mintOne(t, newStore(t, dir, newFakeKeyring()))

	empty := newFakeKeyring()
	_, err := newStore(t, dir, empty).Token("session-1", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrKeyMissing)
	if empty.sets != 0 {
		t.Fatalf("keyring Set called %d times, want 0: a new key would orphan the existing file", empty.sets)
	}
}

func TestFileStore_CorruptAgeFile_FailsClosedWithCorrupt(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	store := newStore(t, dir, kr)
	mintOne(t, store)

	path := pseudonymstore.SessionPath(dir, "session-1") + ".age"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	raw[len(raw)-1] ^= 0xff // break the payload's authentication tag
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = newStore(t, dir, kr).Token("session-1", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrCorrupt)
}

func TestFileStore_NoKeyring_FailsClosedWithKeyringUnavailable(t *testing.T) {
	cases := map[string]pseudonymstore.Keyring{
		"no keyring":          nil,
		"unreachable keyring": &fakeKeyring{secrets: map[string]string{}, err: errNoDBus},
	}
	for name, kr := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := newStore(t, dir, kr).Token("session-1", "DNI", "12345678Z")
			wantErr(t, err, pseudonymstore.ErrKeyringUnavailable)
			if exists(t, pseudonymstore.SessionPath(dir, "session-1")+".age") {
				t.Fatal("a session file was written without a key")
			}
		})
	}
}

func TestFileStore_HostKeyByFD_WinsOverKeyring(t *testing.T) {
	dir := t.TempDir()
	host := newIdentity(t)
	kr := newFakeKeyring()
	kr.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = newIdentity(t).String()

	keys := &pseudonymstore.KeyChain{FD: keyFD(t, "# host key\n"+host.String()+"\n"), Keyring: kr}
	mintOne(t, pseudonymstore.NewFileStore(dir, keys))

	raw, err := os.ReadFile(pseudonymstore.SessionPath(dir, "session-1") + ".age")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if _, err := age.Decrypt(bytesReader(raw), host); err != nil {
		t.Fatalf("session file does not open with the host key: %v", err)
	}
	if kr.sets != 0 {
		t.Fatalf("keyring Set called %d times, want 0 when the host passes a key", kr.sets)
	}
}

func TestFileStore_BrokenHostFD_FailsClosedWithoutFallingBack(t *testing.T) {
	kr := newFakeKeyring()
	cases := []struct {
		name string
		fd   string
		want error
	}{
		{"not a number", "x", pseudonymstore.ErrKeyMissing},
		{"empty descriptor", keyFD(t, ""), pseudonymstore.ErrKeyMissing},
		{"not an age identity", keyFD(t, "hunter2"), pseudonymstore.ErrKeyInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := &pseudonymstore.KeyChain{FD: tc.fd, Keyring: kr}
			_, err := pseudonymstore.NewFileStore(t.TempDir(), keys).Token("session-1", "DNI", "12345678Z")
			wantErr(t, err, tc.want)
		})
	}
	if kr.sets != 0 {
		t.Fatalf("keyring Set called %d times, want 0: a broken host key must not fall back", kr.sets)
	}
}

func TestFileStore_SystemdCredential_WinsOverKeyring_AndAbsentOneFallsThrough(t *testing.T) {
	creds := t.TempDir()
	cred := newIdentity(t)
	if err := os.WriteFile(filepath.Join(creds, pseudonymstore.CredentialName), []byte(cred.String()+"\n"), 0o400); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	kr := newFakeKeyring()
	dir := t.TempDir()
	mintOne(t, pseudonymstore.NewFileStore(dir, &pseudonymstore.KeyChain{CredentialsDir: creds, Keyring: kr}))
	raw, _ := os.ReadFile(pseudonymstore.SessionPath(dir, "session-1") + ".age")
	if _, err := age.Decrypt(bytesReader(raw), cred); err != nil {
		t.Fatalf("session file does not open with the systemd credential: %v", err)
	}
	if kr.sets != 0 {
		t.Fatalf("keyring Set called %d times, want 0 under a systemd credential", kr.sets)
	}

	otherDir := t.TempDir()
	mintOne(t, pseudonymstore.NewFileStore(otherDir, &pseudonymstore.KeyChain{CredentialsDir: t.TempDir(), Keyring: kr, LockPath: otherDir + "/key.lock"}))
	if kr.sets != 1 {
		t.Fatalf("keyring Set called %d times, want 1 when the unit has no veil credential", kr.sets)
	}
}

func TestFileStore_MigratesV1Plaintext_AndRemovesIt(t *testing.T) {
	dir := t.TempDir()
	v1 := `{"mapping":{"DNI:12345678Z":"[DNI-001]"},"reverse":{"[DNI-001]":"12345678Z"},"counters":{"DNI":1}}`
	legacy := filepath.Join(dir, "session-1.json")
	if err := os.WriteFile(legacy, []byte(v1), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	store := newStore(t, dir, newFakeKeyring())

	original, found, err := store.Original("session-1", "[DNI-001]")
	if err != nil || !found || original != "12345678Z" {
		t.Fatalf("Original after migration = (%q, %v, %v), want (12345678Z, true, nil)", original, found, err)
	}
	if exists(t, legacy) {
		t.Fatal("the v1 plaintext file is still on disk after migration")
	}
	if !exists(t, pseudonymstore.SessionPath(dir, "session-1")+".age") {
		t.Fatal("no v2 age file after migration")
	}
	next, err := store.Token("session-1", "DNI", "87654321X")
	if err != nil || next != "[DNI-002]" {
		t.Fatalf("Token after migration = (%q, %v), want ([DNI-002], nil): counters must survive", next, err)
	}
}

func TestFileStore_UnparsableV1_FailsClosedAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "session-1.json")
	if err := os.WriteFile(legacy, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := newStore(t, dir, newFakeKeyring()).Token("session-1", "DNI", "12345678Z")
	wantErr(t, err, pseudonymstore.ErrCorrupt)
	if !exists(t, legacy) && !exists(t, pseudonymstore.SessionPath(dir, "session-1")+".json") {
		t.Fatal("an unmigratable v1 file was removed")
	}
}

func TestFileStore_Reveal_ListsMarkersInOrder(t *testing.T) {
	store := newStore(t, t.TempDir(), newFakeKeyring())
	for _, in := range [][2]string{{"EMAIL", "a@example.com"}, {"DNI", "12345678Z"}, {"DNI", "87654321X"}} {
		if _, err := store.Token("session-1", in[0], in[1]); err != nil {
			t.Fatalf("Token returned unexpected error: %v", err)
		}
	}

	got, err := store.Reveal("session-1")
	if err != nil {
		t.Fatalf("Reveal returned unexpected error: %v", err)
	}
	want := []pseudonymstore.Marker{
		{Marker: "[DNI-001]", Category: "DNI", Value: "12345678Z"},
		{Marker: "[DNI-002]", Category: "DNI", Value: "87654321X"},
		{Marker: "[EMAIL-001]", Category: "EMAIL", Value: "a@example.com"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Reveal = %v, want %v", got, want)
	}
}

func TestFileStore_Reveal_UnknownSession_IsEmptyAndMintsNoKey(t *testing.T) {
	kr := newFakeKeyring()
	got, err := newStore(t, filepath.Join(t.TempDir(), "absent"), kr).Reveal("never-seen")
	if err != nil {
		t.Fatalf("Reveal returned unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Reveal = %v, want no markers", got)
	}
	if kr.sets != 0 {
		t.Fatalf("keyring Set called %d times, want 0: a read must never generate a key", kr.sets)
	}
}

func TestFileStore_Forget_RemovesStoreAndLock(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())
	mintOne(t, store)
	if err := os.WriteFile(filepath.Join(dir, "session-1.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := store.Forget("session-1"); err != nil {
		t.Fatalf("Forget returned unexpected error: %v", err)
	}
	for _, name := range []string{"session-1.age", "session-1.json", "session-1.json.lock"} {
		if exists(t, filepath.Join(dir, name)) {
			t.Errorf("%s still exists after Forget", name)
		}
	}
	if !exists(t, pseudonymstore.SessionPath(dir, "session-1")+".ctr") {
		t.Error("Forget removed the counters file")
	}
	// Same value, new mapping: the old marker is never minted again.
	if token := mintOne(t, store); token != "[DNI-002]" {
		t.Fatalf("Token after Forget = %q, want [DNI-002]", token)
	}
}

func TestFileStore_Forget_UnknownSession_Succeeds(t *testing.T) {
	for _, dir := range []string{t.TempDir(), filepath.Join(t.TempDir(), "absent")} {
		if err := newStore(t, dir, newFakeKeyring()).Forget("never-seen"); err != nil {
			t.Fatalf("Forget(unknown) in %s = %v, want nil", dir, err)
		}
	}
}

func TestFileStore_HeldLock_FailsClosedWithLocked(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir, newFakeKeyring())
	mintOne(t, store)
	pseudonymstore.HoldLock(t, pseudonymstore.SessionPath(dir, "session-1")+".lock")

	_, err := store.Token("session-1", "DNI", "87654321X")
	wantErr(t, err, pseudonymstore.ErrLocked)
}

// TestFileStore_ConcurrentWriters_AreSerialized proves the lock still
// serializes writers: separate instances (as separate veil processes)
// racing on one session each get a distinct token and no counter is lost.
// They share one empty keyring, so it also proves first-use key
// generation runs once.
func TestFileStore_ConcurrentWriters_AreSerialized(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	const writers = 8

	tokens := make([]string, writers)
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = newStore(t, dir, kr).Token("session-1", "DNI", fmt.Sprintf("%08dZ", i))
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	for i := range writers {
		if errs[i] != nil {
			t.Fatalf("writer %d: %v", i, errs[i])
		}
		if seen[tokens[i]] {
			t.Fatalf("token %s minted twice", tokens[i])
		}
		seen[tokens[i]] = true
	}
	if kr.sets != 1 {
		t.Fatalf("keyring Set called %d times, want 1 (one key for all first writers)", kr.sets)
	}
	got, err := newStore(t, dir, kr).Reveal("session-1")
	if err != nil || len(got) != writers {
		t.Fatalf("Reveal = (%d markers, %v), want %d markers", len(got), err, writers)
	}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}
