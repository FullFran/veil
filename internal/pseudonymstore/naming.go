package pseudonymstore

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// File naming (#26). A session's files live at <dir>/ids/<stem>.*, where
// the stem is the session id's bytes in RFC 4648 base32 (section 6),
// lowercase and without padding. Base32 is a bijection on byte strings,
// so two distinct session ids never share a file; its alphabet (a-z2-7)
// is single-case, so a case-insensitive filesystem cannot fold two stems
// into one either (percent-encoding keeps both cases and could), and it
// never yields a separator, "." or a Windows device name.
//
// A stem must also fit the filesystem's name limit (NAME_MAX, 255 bytes
// on the filesystems veil targets) with its longest suffix. An id whose
// base32 form is longer than maxPlainStem gets a hashed stem instead:
// the base32 of its first hashPrefixBytes bytes, "-", and the base32 of
// the SHA-256 (FIPS 180-4) of the whole id. "-" is outside the base32
// alphabet, so a hashed stem never equals a plain one, and two hashed
// stems collide only on a SHA-256 collision. A hashed stem cannot be
// decoded, so the session's first file is <stem>.id, holding the id in
// plaintext (see claim); like the counters file, it is never removed.
//
// The files of every veil before #26 sit directly in <dir>, named by a
// lossy sanitizer (legacyStem). They live in another directory than the
// current ones because any legacy stem is possible ("mfrgg" is both an
// old session id and the base32 of "abc"), while no legacy stem can name
// a file inside ids/. See migrate for how they are carried over.
const (
	idsDir          = "ids"
	maxPlainStem    = 160
	hashPrefixBytes = 60
	// legacyEmptyStem is the stem every session id-less event shared
	// before #26.
	legacyEmptyStem = "unknown-session"
)

var stemEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// loc is where one session's files are: a directory and a stem. id is
// the session id for a current location, empty for a legacy one.
type loc struct {
	dir    string
	stem   string
	id     string
	legacy bool
	hashed bool
}

func (l loc) path(suffix string) string { return filepath.Join(l.dir, l.stem+suffix) }
func (l loc) agePath() string           { return l.path(".age") }
func (l loc) countersPath() string      { return l.path(".ctr") }

// v1Path is the v1 plaintext file. Only a legacy location can have one
// written by veil; a migration moves it into the current location, where
// open turns it into an age file.
func (l loc) v1Path() string { return l.path(".json") }
func (l loc) idPath() string { return l.path(".id") }

// lockPath is the session's process-mutex lock file. A legacy location
// keeps the v1 name every veil before #26 locks.
func (l loc) lockPath() string {
	if l.legacy {
		return l.path(".json.lock")
	}
	return l.path(".lock")
}

// hasStore reports whether the location holds a mapping (age or v1).
func (l loc) hasStore() bool { return exists(l.agePath()) || exists(l.v1Path()) }

// hasAny reports whether the location holds a mapping or a counters file.
func (l loc) hasAny() bool { return l.hasStore() || exists(l.countersPath()) }

// leftoverSuffixes name the interrupted writes a location can hold.
var leftoverSuffixes = []string{".age.tmp", ".json.tmp", ".ctr.tmp"}

// hasLeftover reports whether the location holds an interrupted write.
func (l loc) hasLeftover() bool {
	for _, suffix := range leftoverSuffixes {
		if exists(l.path(suffix)) {
			return true
		}
	}
	return false
}

// SessionPath returns the path, without extension, of sessionID's files
// in a store rooted at dir: <dir>/ids/<stem>. It is for hosts and tests
// that need to know where a session lives; veil itself never takes a
// path from a host.
func SessionPath(dir, sessionID string) string {
	stem, _ := encodeStem(sessionID)
	return filepath.Join(dir, idsDir, stem)
}

// encodeStem returns sessionID's stem and whether it is hashed.
func encodeStem(sessionID string) (string, bool) {
	raw := []byte(sessionID)
	plain := stemEncoding.EncodeToString(raw)
	if len(plain) <= maxPlainStem {
		return plain, false
	}
	sum := sha256.Sum256(raw)
	return stemEncoding.EncodeToString(raw[:hashPrefixBytes]) + "-" + stemEncoding.EncodeToString(sum[:]), true
}

// legacyStem is the file stem every veil before #26 gave sessionID: "/",
// "\" and ".." replaced by "_", and "unknown-session" for an empty id.
func legacyStem(sessionID string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(sessionID)
	if safe == "" {
		safe = legacyEmptyStem
	}
	return safe
}

// ambiguousLegacy reports whether more than one session id can have
// produced the legacy stem. The sanitizer writes "_" for every
// replacement and "unknown-session" for an empty id, so a stem with
// neither is the session id itself and nothing else.
func ambiguousLegacy(stem string) bool {
	return strings.Contains(stem, "_") || stem == legacyEmptyStem
}

func (s *FileStore) idsPath() string { return filepath.Join(s.dir, idsDir) }

// current returns where sessionID's files are now.
func (s *FileStore) current(sessionID string) loc {
	stem, hashed := encodeStem(sessionID)
	return loc{dir: s.idsPath(), stem: stem, id: sessionID, hashed: hashed}
}

// legacyOf returns where a veil before #26 kept sessionID's files.
func (s *FileStore) legacyOf(sessionID string) loc {
	return loc{dir: s.dir, stem: legacyStem(sessionID), legacy: true}
}

// legacyAt returns the legacy location of a stem found on disk.
func (s *FileStore) legacyAt(stem string) loc {
	return loc{dir: s.dir, stem: stem, legacy: true}
}

// idOf returns the session id a current stem names: decoded for a plain
// stem, read from the .id file for a hashed one. ok is false when the
// stem is not one veil writes (not canonical base32, or an .id file that
// is missing or names an id with another stem).
func (s *FileStore) idOf(stem string) (string, bool) {
	var id string
	if strings.Contains(stem, "-") {
		raw, err := os.ReadFile(filepath.Join(s.idsPath(), stem+".id")) // #nosec G304 -- a file name listed from the store's own ids directory
		if err != nil {
			return "", false
		}
		id = string(raw)
	} else {
		raw, err := stemEncoding.DecodeString(stem)
		if err != nil {
			return "", false
		}
		id = string(raw)
	}
	if got, _ := encodeStem(id); id == "" || got != stem {
		return "", false
	}
	return id, true
}

// claim writes a hashed location's .id file before any other file of the
// session, so the stem can always be named, and checks it on every
// opening. A plain stem needs none. An .id file naming another id fails
// closed: it would be a SHA-256 collision, or tampering. A missing one is
// written again: the stem is the SHA-256 of the id the caller names, so
// that id is provably the session's. The caller holds the session lock.
func (s *FileStore) claim(l loc) error {
	if !l.hashed {
		return nil
	}
	raw, err := os.ReadFile(l.idPath())
	switch {
	case err == nil:
		if string(raw) != l.id {
			return fmt.Errorf("%w: the session id file names another session", ErrCorrupt)
		}
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("pseudonymstore: read session id file: %w", err)
	}
	return writeDurable(l.dir, l.idPath(), []byte(l.id))
}

// ensureDirs creates the store directory and its ids directory (0700) and
// makes sure both are private.
func (s *FileStore) ensureDirs() error {
	for _, dir := range []string{s.dir, s.idsPath()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("pseudonymstore: create %s: %w", dir, err)
		}
		if err := securePrivateDir(dir); err != nil {
			return err
		}
	}
	return nil
}
