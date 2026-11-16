package pseudonymstore_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

// fakeKeyring is an in-memory pseudonymstore.Keyring. Every test uses it
// (or no keyring at all), so the suite never reads or writes the real OS
// keyring of the machine that runs it.
type fakeKeyring struct {
	mu      sync.Mutex
	secrets map[string]string
	err     error // when set, every call fails as an unreachable keyring
	sets    int
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
	f.sets++
	f.secrets[service+"/"+account] = secret
	return nil
}

var errNoDBus = errors.New("no D-Bus session")

// newStore builds a FileStore over dir whose key lives in keyring.
func newStore(t *testing.T, dir string, keyring pseudonymstore.Keyring) *pseudonymstore.FileStore {
	t.Helper()
	return pseudonymstore.NewFileStore(dir, &pseudonymstore.KeyChain{Keyring: keyring, LockPath: dir + "/key.lock"})
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
