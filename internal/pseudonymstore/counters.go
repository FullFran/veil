package pseudonymstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// countersFile is <session>.ctr: the next-marker counter per category of a
// session, kept outside the encrypted mapping and kept when the session is
// swept or forgotten.
//
// Why: the host's history of a session still holds the markers veil sent
// (say [DNI-001] for value A). If the session is removed and later
// resumed, minting from zero would give a new value B the marker
// [DNI-001] again: the model would see two people as one, and rehydrating
// the old [DNI-001] in a write would put B on disk where A was meant. With
// the counters kept, numbering carries on and a removed marker is simply
// unknown (rehydration leaves it as it is).
//
// It holds no value, no mapping and no marker, only how many values of
// each category the session has seen, so it is not the "additional
// information" of GDPR art. 4(5). It is plaintext, so forget and sweep,
// which need no key, can keep it; whoever can rewrite it can also delete
// the whole store. It is never swept: deleting it reopens the reuse it
// exists to prevent.
//
// When a session is removed and its counters cannot be read (a session
// written before counters files existed, removed without a key that opens
// it), the file is a tombstone instead: {"version":1,"retired":true}.
// Removal still happens, and minting for that session id then fails
// closed with ErrSessionRetired, since any number could repeat one the
// host's history already holds.
type countersFile struct {
	Version  int            `json:"version"`
	Counters map[string]int `json:"counters,omitempty"`
	Retired  bool           `json:"retired,omitempty"`
}

const countersVersion = 1

// raiseCounters lifts data's counters to at least the counters file's, so
// numbering continues after a removal.
func (s *FileStore) raiseCounters(sessionID string, data *sessionFile) error {
	raw, err := os.ReadFile(s.countersPath(sessionID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pseudonymstore: read counters: %w", err)
	}
	var c countersFile
	if err := json.Unmarshal(raw, &c); err != nil || c.Version != countersVersion {
		// Starting from zero could reuse a marker: fail closed.
		return fmt.Errorf("%w: counters file", ErrCorrupt)
	}
	if c.Retired {
		return ErrSessionRetired
	}
	for category, n := range c.Counters {
		if n > data.Counters[category] {
			data.Counters[category] = n
		}
	}
	return nil
}

// writeCounters durably replaces the session's counters file. The caller
// holds the session lock.
func (s *FileStore) writeCounters(sessionID string, counters map[string]int) error {
	return s.writeCountersFile(sessionID, countersFile{Version: countersVersion, Counters: counters})
}

// retire writes the session's tombstone (see countersFile).
func (s *FileStore) retire(sessionID string) error {
	return s.writeCountersFile(sessionID, countersFile{Version: countersVersion, Retired: true})
}

func (s *FileStore) writeCountersFile(sessionID string, c countersFile) error {
	encoded, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("pseudonymstore: encode counters: %w", err)
	}
	path := s.countersPath(sessionID)
	if err := writeSynced(path+".tmp", encoded); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return fmt.Errorf("pseudonymstore: rename counters: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		return fmt.Errorf("pseudonymstore: sync dir: %w", err)
	}
	return nil
}

// readOnly reads a session's mapping without writing anything (no
// migration, no key generation): the age file when the key opens it, else
// a v1 plaintext file. The caller holds the session lock.
func (s *FileStore) readOnly(sessionID string) (*sessionFile, error) {
	if raw, err := os.ReadFile(s.agePath(sessionID)); err == nil {
		return s.decrypt(raw)
	}
	raw, err := os.ReadFile(s.legacyPath(sessionID))
	if err != nil {
		return nil, err
	}
	return parse(raw)
}
