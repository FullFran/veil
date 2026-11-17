package pseudonymstore

import (
	"fmt"
	"os"
)

// migrateStep runs after each file a migration moves. It is a variable
// only so tests can stop a migration midway, as a crash would.
var migrateStep = func(suffix string) error { return nil }

// migrate carries a session's pre-#26 files (see naming.go) over to its
// current location c. The caller holds c's lock; migrate takes the legacy
// lock too (the name every veil before #26 locks), always in that order.
//
// An unambiguous legacy stem (see ambiguousLegacy) is the session id
// itself, so its files are this session's: adopt moves them. Any session
// operation does it, and it needs no key.
//
// An ambiguous legacy stem holds the mixed mapping of every id that
// mapped to it, so its mapping is never read for any of them: it stays
// under its old name, which `veil store find`, `forget --legacy-stem`
// and retention still reach. Only its counters cross over, and only
// before the session first mints (mint), since the host history of each
// of those ids may hold the stem's markers: see seed.
func (s *FileStore) migrate(c loc, mint bool) error {
	l := s.legacyOf(c.id)
	ambiguous := ambiguousLegacy(l.stem)
	if !l.hasAny() && (ambiguous || !l.hasLeftover()) {
		return nil
	}
	if ambiguous && (!mint || c.hasAny()) {
		return nil
	}
	unlock, err := acquireLock(l.lockPath())
	if err != nil {
		return err
	}
	defer unlock()
	if ambiguous {
		return s.seed(l, c)
	}
	return s.adopt(l, c)
}

// adopt moves a legacy location's counters, age and v1 files to c, one
// rename each, then removes its interrupted writes (a v1 one holds
// plaintext) and syncs both directories. Every step can be repeated, so a
// crash midway is finished by the next use of the session. A file already
// at its new name while its legacy one is still there is never
// overwritten or merged: it fails closed, unless both names are one file.
func (s *FileStore) adopt(l, c loc) error {
	if err := s.claim(c); err != nil {
		return err
	}
	for _, suffix := range []string{".ctr", ".age", ".json"} {
		src, dst := l.path(suffix), c.path(suffix)
		if !exists(src) {
			continue
		}
		if exists(dst) {
			if !sameFile(src, dst) {
				return fmt.Errorf("%w: a legacy and a current file of the session both exist", ErrCorrupt)
			}
			if err := removeIfExists(src); err != nil {
				return err
			}
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("pseudonymstore: migrate: %w", err)
		}
		if err := migrateStep(suffix); err != nil {
			return err
		}
	}
	for _, suffix := range leftoverSuffixes {
		if err := removeIfExists(l.path(suffix)); err != nil {
			return err
		}
	}
	for _, dir := range []string{c.dir, l.dir} {
		if err := syncDir(dir); err != nil {
			return fmt.Errorf("pseudonymstore: sync dir: %w", err)
		}
	}
	return nil
}

// seed gives c the counters of an ambiguous legacy location, so the
// session never mints a marker number the stem already used: the
// counters file, else the counters inside its mapping (which needs the
// key; a mapping that cannot be read fails closed). A retired legacy stem
// retires c. No value and no marker crosses over.
func (s *FileStore) seed(l, c loc) error {
	file, found, err := readCountersFile(l)
	if err != nil {
		return err
	}
	counters := file.Counters
	switch {
	case found && file.Retired:
		return s.retire(c)
	case !found && l.hasStore():
		data, err := s.readOnly(l)
		if err != nil {
			return err
		}
		counters = data.Counters
	}
	if len(counters) == 0 {
		return nil
	}
	return s.writeCounters(c, counters)
}

func sameFile(a, b string) bool {
	ai, err := os.Lstat(a)
	if err != nil {
		return false
	}
	bi, err := os.Lstat(b)
	return err == nil && os.SameFile(ai, bi)
}
