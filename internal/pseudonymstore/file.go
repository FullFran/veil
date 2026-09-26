// Package pseudonymstore is the production adapter for
// domain.PseudonymStore: a session-scoped mapping file on disk.
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
package pseudonymstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sessionFile is the on-disk shape of one session's mapping.
type sessionFile struct {
	// Mapping is keyed by "category:original" and holds the token
	// already minted for it.
	Mapping map[string]string `json:"mapping"`
	// Counters holds the next-token counter per category.
	Counters map[string]int `json:"counters"`
}

// FileStore implements domain.PseudonymStore by keeping one JSON file per
// session, at <dir>/<sessionID>.json, created with 0600 permissions.
type FileStore struct {
	dir string
}

// NewFileStore builds a FileStore rooted at dir. dir is created (0700) on
// first write if it does not already exist.
func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
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

// sessionPath returns the JSON file path for sessionID, sanitized to a
// safe filename so a hostile or malformed session ID can never escape dir
// via a path separator or "..".
func (s *FileStore) sessionPath(sessionID string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(sessionID)
	if safe == "" {
		safe = "unknown-session"
	}
	return filepath.Join(s.dir, safe+".json")
}

// lockPath returns the process-mutex lock file path for sessionID.
func (s *FileStore) lockPath(sessionID string) string {
	return s.sessionPath(sessionID) + ".lock"
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

	unlock, err := s.acquireLock(sessionID)
	if err != nil {
		return "", err
	}
	defer unlock()

	path := s.sessionPath(sessionID)
	data, err := s.load(path)
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

	if err := s.save(path, data); err != nil {
		return "", err
	}
	return token, nil
}

// load reads path's session mapping, treating a missing file as an empty,
// freshly initialized mapping, and any other read or parse failure as a
// fail-closed error: veil must never silently start over on a corrupted
// mapping, since that could reuse a token number already sent to the
// model for a different original value.
func (s *FileStore) load(path string) (*sessionFile, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &sessionFile{Mapping: map[string]string{}, Counters: map[string]int{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pseudonymstore: read %s: %w", path, err)
	}

	var data sessionFile
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("pseudonymstore: parse %s (refusing to overwrite a corrupted session file): %w", path, err)
	}
	if data.Mapping == nil {
		data.Mapping = map[string]string{}
	}
	if data.Counters == nil {
		data.Counters = map[string]int{}
	}
	return &data, nil
}

// save writes data to path with 0600 permissions via a temp-file-plus-
// rename so a crash mid-write can never leave a half-written, corrupted
// session file behind.
func (s *FileStore) save(path string, data *sessionFile) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("pseudonymstore: encode %s: %w", path, err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return fmt.Errorf("pseudonymstore: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("pseudonymstore: rename %s to %s: %w", tmp, path, err)
	}
	return nil
}

// acquireLock takes a simple create-exclusive lock file, retrying briefly
// on contention, and returns a function that releases it. It fails
// closed (returns an error) rather than blocking forever if the lock
// cannot be acquired within a short deadline, since a stuck lock must
// eventually surface as a blocked event, not a silently skipped rewrite.
func (s *FileStore) acquireLock(sessionID string) (release func(), err error) {
	path := s.lockPath(sessionID)
	deadline := time.Now().Add(2 * time.Second)

	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("pseudonymstore: acquire lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("pseudonymstore: timed out waiting for lock %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
