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

// readCountersFile reads l's counters file. found is false when it does
// not exist. One that cannot be parsed fails closed: starting from zero
// could reuse a marker.
func readCountersFile(l loc) (c countersFile, found bool, err error) {
	raw, err := os.ReadFile(l.countersPath())
	if errors.Is(err, fs.ErrNotExist) {
		return countersFile{}, false, nil
	}
	if err != nil {
		return countersFile{}, false, fmt.Errorf("pseudonymstore: read counters: %w", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Version != countersVersion {
		return countersFile{}, false, fmt.Errorf("%w: counters file", ErrCorrupt)
	}
	return c, true, nil
}

// raiseCounters lifts data's counters to at least the counters file's, so
// numbering continues after a removal.
func (s *FileStore) raiseCounters(l loc, data *sessionFile) error {
	c, found, err := readCountersFile(l)
	if err != nil || !found {
		return err
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
func (s *FileStore) writeCounters(l loc, counters map[string]int) error {
	return s.writeCountersFile(l, countersFile{Version: countersVersion, Counters: counters})
}

// retire writes the session's tombstone (see countersFile).
func (s *FileStore) retire(l loc) error {
	return s.writeCountersFile(l, countersFile{Version: countersVersion, Retired: true})
}

// writeCountersFile is the first write of any new session (save writes
// the counters before the mapping), so it claims a hashed location first.
func (s *FileStore) writeCountersFile(l loc, c countersFile) error {
	if err := s.claim(l); err != nil {
		return err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("pseudonymstore: encode counters: %w", err)
	}
	return writeDurable(l.dir, l.countersPath(), encoded)
}

// writeDurable replaces path with data through a synced temp file, a
// rename and a synced directory (dir, path's own), so the new content is
// whole and durable when it returns.
func writeDurable(dir, path string, data []byte) error {
	if err := writeSynced(path+".tmp", data); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return fmt.Errorf("pseudonymstore: rename: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("pseudonymstore: sync dir: %w", err)
	}
	return nil
}

// readOnly reads a session's mapping without writing anything (no
// migration, no key generation): the age file when the key opens it, else
// a v1 plaintext file. The caller holds the session lock.
func (s *FileStore) readOnly(l loc) (*sessionFile, error) {
	if raw, err := os.ReadFile(l.agePath()); err == nil {
		return s.decrypt(raw)
	}
	raw, err := os.ReadFile(l.v1Path())
	if err != nil {
		return nil, err
	}
	return parse(raw)
}
