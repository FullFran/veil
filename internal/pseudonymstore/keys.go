package pseudonymstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"filippo.io/age"
)

// Key sources, in the order KeyChain tries them.
const (
	// KeyFDEnv names the environment variable that holds the number of an
	// inherited file descriptor a host writes the store key to. Only the
	// descriptor number travels in the environment, never the key: the
	// environment of a process is readable by the same user through
	// /proc/<pid>/environ.
	KeyFDEnv = "VEIL_KEY_FD"
	// CredentialName is the systemd credential veil reads from
	// $CREDENTIALS_DIRECTORY (LoadCredential= / LoadCredentialEncrypted=).
	CredentialName = "veil-store-key"
	// KeyringService and KeyringAccount name the OS keyring entry that
	// holds the generated key when no host or systemd key is given.
	KeyringService = "veil"
	KeyringAccount = "pseudonym-store-key"

	// maxKeyBytes bounds how much veil reads from a key source. An age
	// identity is 74 bytes; the bound only stops a runaway pipe.
	maxKeyBytes = 64 << 10
)

// ErrKeyringNotFound is what a Keyring returns from Get when it holds no
// entry for the service and account.
var ErrKeyringNotFound = errors.New("pseudonymstore: no entry in keyring")

// Keyring is the OS secret store veil keeps a generated key in. It is an
// interface so tests inject a fake and never touch the real keyring.
type Keyring interface {
	// Get returns the secret, ErrKeyringNotFound when there is none, or
	// another error when the keyring cannot be reached.
	Get(service, account string) (string, error)
	// Set stores the secret, replacing any previous one.
	Set(service, account, secret string) error
}

// Keys resolves the age identity the store encrypts to and decrypts with.
type Keys interface {
	// Identity returns the store's identity. create allows a key source
	// that can mint keys (the OS keyring) to generate one when it has
	// none; it is true only when no encrypted session exists yet, so a
	// new key can never orphan an existing file.
	Identity(create bool) (*age.X25519Identity, error)
}

// KeyChain implements Keys over veil's key sources, in order: a host key
// by inherited descriptor (FD), a systemd credential (CredentialsDir),
// then the OS keyring. A host that sets FD always wins, and a broken FD
// never falls through to another source: a host wiring mistake must fail
// closed, not silently use a different key.
type KeyChain struct {
	// FD is the value of VEIL_KEY_FD, empty when the host passes no key.
	FD string
	// CredentialsDir is $CREDENTIALS_DIRECTORY, empty outside systemd.
	CredentialsDir string
	// Keyring is the OS keyring; nil means none is available.
	Keyring Keyring
	// LockPath serializes key generation across processes, so two first
	// writes racing cannot store two different keys.
	LockPath string

	mu       sync.Mutex
	identity *age.X25519Identity
}

// NewKeyChainFromEnv builds the KeyChain veil uses in production, reading
// VEIL_KEY_FD and CREDENTIALS_DIRECTORY from the environment and locking
// key generation under dir.
func NewKeyChainFromEnv(dir string, keyring Keyring) *KeyChain {
	return &KeyChain{
		FD:             os.Getenv(KeyFDEnv),
		CredentialsDir: os.Getenv("CREDENTIALS_DIRECTORY"),
		Keyring:        keyring,
		LockPath:       filepath.Join(dir, "key.lock"),
	}
}

// Identity implements Keys. A resolved identity is cached for the life of
// the KeyChain: a descriptor can be read only once.
func (k *KeyChain) Identity(create bool) (*age.X25519Identity, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.identity != nil {
		return k.identity, nil
	}
	id, err := k.resolve(create)
	if err != nil {
		return nil, err
	}
	k.identity = id
	return id, nil
}

func (k *KeyChain) resolve(create bool) (*age.X25519Identity, error) {
	if k.FD != "" {
		return k.fromFD()
	}
	if k.CredentialsDir != "" {
		raw, err := os.ReadFile(filepath.Join(k.CredentialsDir, CredentialName))
		switch {
		case err == nil:
			return parseIdentity(raw)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("%w: systemd credential cannot be read", ErrKeyMissing)
		}
		// The unit has credentials, but not veil's: use the keyring.
	}
	return k.fromKeyring(create)
}

func (k *KeyChain) fromFD() (*age.X25519Identity, error) {
	fd, err := strconv.Atoi(k.FD)
	if err != nil || fd < 0 {
		return nil, fmt.Errorf("%w: %s is not a descriptor number", ErrKeyMissing, KeyFDEnv)
	}
	f := os.NewFile(uintptr(fd), KeyFDEnv)
	if f == nil {
		return nil, fmt.Errorf("%w: %s is not a valid descriptor", ErrKeyMissing, KeyFDEnv)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be read", ErrKeyMissing, KeyFDEnv)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrKeyMissing, KeyFDEnv)
	}
	return parseIdentity(raw)
}

func (k *KeyChain) fromKeyring(create bool) (*age.X25519Identity, error) {
	if k.Keyring == nil {
		return nil, ErrKeyringUnavailable
	}
	id, err := k.keyringGet()
	if err == nil || !errors.Is(err, ErrKeyringNotFound) {
		return id, err
	}
	if !create {
		return nil, fmt.Errorf("%w: the keyring holds no store key", ErrKeyMissing)
	}

	unlock, err := acquireLock(k.LockPath)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Another process may have generated the key while this one waited.
	id, err = k.keyringGet()
	if err == nil || !errors.Is(err, ErrKeyringNotFound) {
		return id, err
	}

	id, err = age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("pseudonymstore: generate key: %w", err)
	}
	if err := k.Keyring.Set(KeyringService, KeyringAccount, id.String()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyringUnavailable, err)
	}
	return id, nil
}

// keyringGet reads and parses the keyring entry. It returns an error that
// wraps ErrKeyringNotFound when there is none.
func (k *KeyChain) keyringGet() (*age.X25519Identity, error) {
	secret, err := k.Keyring.Get(KeyringService, KeyringAccount)
	switch {
	case errors.Is(err, ErrKeyringNotFound):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrKeyringUnavailable, err)
	}
	return parseIdentity([]byte(secret))
}

// parseIdentity reads an age identity file (the format age-keygen writes,
// comments allowed) and returns its first X25519 identity. The parse
// error is dropped on purpose: it could quote key material.
func parseIdentity(raw []byte) (*age.X25519Identity, error) {
	ids, err := age.ParseIdentities(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: not an age identity", ErrKeyInvalid)
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, fmt.Errorf("%w: no X25519 age identity", ErrKeyInvalid)
}
