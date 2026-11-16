// Package pseudonymstore is the production adapter for
// domain.PseudonymStore: a session-scoped, encrypted mapping file on disk.
//
// Why a file and not an in-memory map: OpenCode's shim
// (adapters/opencode/veil-plugin.js) spawns the `veil` binary fresh for
// every single hook call, per the README's own description of the
// process model. Nothing survives in a Go process's memory between one
// `tool.execute.before` call and the next `chat.message` call a moment
// later; they are different processes. A pseudonym mapping that must stay
// stable for the whole life of an OpenCode session therefore has to live
// somewhere both invocations can reach: a file, keyed by the OpenCode
// session ID, under the OS's state/temp directory. This package is that
// file.
//
// Format v2: each session is one age v1 file (C2SP age-encryption.org/v1)
// at <dir>/<session>.age, encrypted to the store's X25519 identity (see
// Keys). The plaintext inside is the JSON sessionFile below, so no real
// value and no "category:original" key is on disk in clear. A v1
// plaintext <session>.json is migrated on first access and then removed.
//
// Retention (TTL) is not decided here: Forget is the one deletion path,
// so a retention sweep calls it per expired session, and each write is a
// fresh rename, so a session file's mtime is its last write.
package pseudonymstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// formatVersion is the version of the plaintext inside an age session
// file. v1 was the unencrypted <session>.json, which had no version field.
const formatVersion = 2

// sessionFile is the shape of one session's mapping.
type sessionFile struct {
	// Version is formatVersion for an encrypted file, 0 for a v1 file.
	Version int `json:"version,omitempty"`
	// Mapping is keyed by "category:original" and holds the token
	// already minted for it.
	Mapping map[string]string `json:"mapping"`
	// Reverse is keyed by token and holds the original value, for
	// rehydrating a tool call that writes real data to disk.
	Reverse map[string]string `json:"reverse"`
	// Counters holds the next-token counter per category.
	Counters map[string]int `json:"counters"`
}

func emptySession() *sessionFile {
	return &sessionFile{Mapping: map[string]string{}, Reverse: map[string]string{}, Counters: map[string]int{}}
}

// Marker is one pseudonym of a session and the value it stands for.
type Marker struct {
	Marker   string `json:"marker"`
	Category string `json:"category"`
	Value    string `json:"value"`
}

// FileStore implements domain.PseudonymStore by keeping one age file per
// session, at <dir>/<sessionID>.age, created with 0600 permissions.
type FileStore struct {
	dir  string
	keys Keys
}

// NewFileStore builds a FileStore rooted at dir whose files are encrypted
// with the identity keys resolves. dir is created (0700) on first write
// if it does not already exist.
func NewFileStore(dir string, keys Keys) *FileStore {
	return &FileStore{dir: dir, keys: keys}
}

// DefaultDir returns the default root FileStore should use: under
// $XDG_STATE_HOME/veil/sessions when XDG_STATE_HOME is set (the
// conventional location for this kind of mutable-but-not-configuration
// state on Linux), otherwise under the OS temp directory.
func DefaultDir() string {
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		return filepath.Join(stateHome, "veil", "sessions")
	}
	return filepath.Join(os.TempDir(), "veil-sessions")
}

// basePath returns the session's path without extension, sanitized to a
// safe filename so a hostile or malformed session ID can never escape dir
// via a path separator or "..".
func (s *FileStore) basePath(sessionID string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(sessionID)
	if safe == "" {
		safe = "unknown-session"
	}
	return filepath.Join(s.dir, safe)
}

func (s *FileStore) agePath(sessionID string) string    { return s.basePath(sessionID) + ".age" }
func (s *FileStore) legacyPath(sessionID string) string { return s.basePath(sessionID) + ".json" }

// lockPath returns the process-mutex lock file path for sessionID. It
// keeps the v1 name, so a v1 and a v2 binary running side by side during
// an upgrade still serialize on the same lock.
func (s *FileStore) lockPath(sessionID string) string {
	return s.legacyPath(sessionID) + ".lock"
}

// Token implements domain.PseudonymStore. It takes a simple create-file
// advisory lock (a sibling ".lock" file created with O_EXCL) around the
// read-modify-write cycle, so two veil processes racing to handle two
// hook calls from the same OpenCode session in close succession cannot
// interleave and corrupt each other's counters.
func (s *FileStore) Token(sessionID, category, original string) (string, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", fmt.Errorf("pseudonymstore: create %s: %w", s.dir, err)
	}

	unlock, err := acquireLock(s.lockPath(sessionID))
	if err != nil {
		return "", err
	}
	defer unlock()

	data, err := s.open(sessionID)
	if err != nil {
		return "", err
	}

	key := category + ":" + original
	if token, ok := data.Mapping[key]; ok {
		return token, nil
	}

	data.Counters[category]++
	token := fmt.Sprintf("[%s-%03d]", category, data.Counters[category])
	data.Mapping[key] = token
	data.Reverse[token] = original

	if err := s.save(sessionID, data); err != nil {
		return "", err
	}
	return token, nil
}

// Original implements domain.PseudonymStore's reverse lookup, guarded by
// the same lock and fail-closed load as Token.
func (s *FileStore) Original(sessionID, token string) (string, bool, error) {
	data, err := s.read(sessionID)
	if err != nil {
		return "", false, err
	}
	original, found := data.Reverse[token]
	return original, found, nil
}

// Reveal returns every marker of the session and its real value, sorted
// by category and then by number, for a host's own "what veil hid" view.
// An unknown session has no markers.
func (s *FileStore) Reveal(sessionID string) ([]Marker, error) {
	data, err := s.read(sessionID)
	if err != nil {
		return nil, err
	}

	markers := make([]Marker, 0, len(data.Mapping))
	for key, token := range data.Mapping {
		category, _, _ := strings.Cut(key, ":")
		markers = append(markers, Marker{Marker: token, Category: category, Value: data.Reverse[token]})
	}
	sort.Slice(markers, func(i, j int) bool {
		a, b := markers[i], markers[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if len(a.Marker) != len(b.Marker) {
			return len(a.Marker) < len(b.Marker)
		}
		return a.Marker < b.Marker
	})
	return markers, nil
}

// Forget removes the session's store (the age file, any v1 plaintext file
// and an interrupted write) and then its lock. It holds the lock while it
// deletes, so it never removes a file under a writer. Forgetting an
// unknown session succeeds. It needs no key.
func (s *FileStore) Forget(sessionID string) error {
	if _, err := os.Stat(s.dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	unlock, err := acquireLock(s.lockPath(sessionID))
	if err != nil {
		return err
	}
	defer unlock()

	for _, path := range []string{s.agePath(sessionID), s.legacyPath(sessionID), s.agePath(sessionID) + ".tmp"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("pseudonymstore: remove: %w", err)
		}
	}
	return nil
}

// read loads a session for a read-only operation. A session with no file
// at all is empty and needs neither the lock nor a key, so a read never
// generates a key.
func (s *FileStore) read(sessionID string) (*sessionFile, error) {
	if !exists(s.agePath(sessionID)) && !exists(s.legacyPath(sessionID)) {
		return emptySession(), nil
	}

	unlock, err := acquireLock(s.lockPath(sessionID))
	if err != nil {
		return nil, err
	}
	defer unlock()

	return s.open(sessionID)
}

// open loads the session under its lock. An age file is decrypted; a
// leftover v1 file beside it (a migration interrupted after the write) is
// removed. A v1 file alone is migrated: written as an age file, then
// removed. No file at all is a fresh, empty session. Every failure fails
// closed: veil must never silently start over on a mapping it cannot
// read, since that could reuse a token number already sent to the model
// for a different original value.
func (s *FileStore) open(sessionID string) (*sessionFile, error) {
	raw, err := os.ReadFile(s.agePath(sessionID))
	switch {
	case err == nil:
		data, err := s.decrypt(raw)
		if err != nil {
			return nil, err
		}
		if err := removeIfExists(s.legacyPath(sessionID)); err != nil {
			return nil, err
		}
		return data, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("pseudonymstore: read: %w", err)
	}

	legacy, err := os.ReadFile(s.legacyPath(sessionID))
	if errors.Is(err, fs.ErrNotExist) {
		return emptySession(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("pseudonymstore: read v1: %w", err)
	}
	data, err := parse(legacy)
	if err != nil {
		return nil, err
	}
	if err := s.save(sessionID, data); err != nil {
		return nil, err
	}
	if err := removeIfExists(s.legacyPath(sessionID)); err != nil {
		return nil, err
	}
	return data, nil
}

// decrypt opens an age session file. An identity that matches no
// recipient is a wrong key; anything else that fails (header, payload
// authentication, JSON) is a corrupt file.
func (s *FileStore) decrypt(raw []byte) (*sessionFile, error) {
	id, err := s.keys.Identity(false)
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(bytes.NewReader(raw), id)
	var noMatch *age.NoIdentityMatchError
	switch {
	case errors.As(err, &noMatch):
		return nil, fmt.Errorf("%w: the key does not open the session file", ErrKeyInvalid)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}

	data, err := parse(plain)
	if err != nil {
		return nil, err
	}
	if data.Version != formatVersion {
		return nil, fmt.Errorf("%w: unsupported format version %d", ErrCorrupt, data.Version)
	}
	return data, nil
}

// parse decodes a session mapping's JSON.
func parse(raw []byte) (*sessionFile, error) {
	var data sessionFile
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w (refusing to overwrite it): %w", ErrCorrupt, err)
	}
	if data.Mapping == nil {
		data.Mapping = map[string]string{}
	}
	if data.Reverse == nil {
		data.Reverse = map[string]string{}
	}
	if data.Counters == nil {
		data.Counters = map[string]int{}
	}
	return &data, nil
}

// save encrypts data and writes it with 0600 permissions via a temp-file-
// plus-rename, so a crash mid-write can never leave a half-written,
// corrupted session file behind. It may generate the store key (keyring
// first use): only a write, under the session lock, ever does.
func (s *FileStore) save(sessionID string, data *sessionFile) error {
	id, err := s.keys.Identity(true)
	if err != nil {
		return err
	}

	data.Version = formatVersion
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("pseudonymstore: encode: %w", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		return fmt.Errorf("pseudonymstore: encrypt: %w", err)
	}
	if _, err := w.Write(encoded); err != nil {
		return fmt.Errorf("pseudonymstore: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("pseudonymstore: encrypt: %w", err)
	}

	path := s.agePath(sessionID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("pseudonymstore: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("pseudonymstore: rename: %w", err)
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("pseudonymstore: remove: %w", err)
	}
	return nil
}

// acquireLock takes a simple create-exclusive lock file, retrying briefly
// on contention, and returns a function that releases it. It fails
// closed with ErrLocked rather than blocking forever if the lock cannot
// be acquired within a short deadline, since a stuck lock must eventually
// surface as a blocked event, not a silently skipped rewrite.
func acquireLock(path string) (release func(), err error) {
	deadline := time.Now().Add(2 * time.Second)

	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("pseudonymstore: acquire lock: %w", err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: timed out waiting for %s", ErrLocked, path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
