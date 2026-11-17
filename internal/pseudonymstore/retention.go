package pseudonymstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

// SweepResult is what a retention sweep did, by session id.
type SweepResult struct {
	// Forgotten sessions were unused for longer than the TTL and removed.
	Forgotten []string `json:"forgotten"`
	// Skipped sessions were expired but another process held their lock;
	// they are never removed under a holder.
	Skipped []string `json:"skipped"`
	// Failed sessions could not be locked or removed; the sweep went on
	// with the rest.
	Failed []string `json:"failed"`
	// LegacyStems is the same for store files a veil before #26 left
	// under a name several session ids could have produced (see
	// ambiguousLegacy): they are reported by that name, never as a
	// session id, since their session id cannot be known.
	LegacyStems LegacySweep `json:"legacy_stems"`
}

// LegacySweep is what a sweep did to legacy stems (see SweepResult).
type LegacySweep struct {
	Forgotten []string `json:"forgotten"`
	Skipped   []string `json:"skipped"`
	Failed    []string `json:"failed"`
}

// NewSweepResult returns a result with every list empty, not null.
func NewSweepResult() SweepResult {
	return SweepResult{
		Forgotten: []string{}, Skipped: []string{}, Failed: []string{},
		LegacyStems: LegacySweep{Forgotten: []string{}, Skipped: []string{}, Failed: []string{}},
	}
}

// sweepLocked runs after Sweep takes a session's lock, before its
// re-check, with the session id (or the legacy stem). It is a variable
// only so tests can use a session meanwhile.
var sweepLocked = func(name string) {}

// Holding is one session whose store holds a searched value: the session
// id and the categories the value was pseudonymized under, never a value.
// A store a veil before #26 left under a name several session ids could
// have produced has no knowable session id: it is reported by that name
// in LegacyStem instead, and erased with ForgetLegacy.
type Holding struct {
	Session    string   `json:"session,omitempty"`
	LegacyStem string   `json:"legacy_stem,omitempty"`
	Categories []string `json:"categories"`
}

// entry is one store on disk: where it is and what to report it as. id
// is the real session id; it is empty only for an ambiguous legacy stem.
type entry struct {
	loc loc
	id  string
}

// name is what a report calls the entry: its session id, else its stem.
func (e entry) name() string {
	if e.id != "" {
		return e.id
	}
	return e.loc.stem
}

// Sweep removes every session unused for longer than ttl (GDPR art.
// 5(1)(e) storage limitation), at most limit of them when limit is
// positive. A session's last use is its file's mtime (see FileStore), so
// the sweep needs no key: a lost key never blocks deletion. It never
// waits for and never removes a session another process holds locked; it
// re-checks the last use under the lock, since the holder may just have
// used the session, and deletes through removeLocked, the same path as
// Forget. A session it cannot lock or remove is reported failed and the
// sweep goes on with the rest; the error then joins every failure.
// Legacy files are swept where they are, without migrating them.
func (s *FileStore) Sweep(ttl time.Duration, limit int) (SweepResult, error) {
	result := NewSweepResult()
	entries, err := s.entries()
	if err != nil {
		return result, err
	}
	now := s.now()
	var failures []error
	done := 0
	for _, e := range entries {
		if limit > 0 && done >= limit {
			break
		}
		if !expired(e.loc, now, ttl) {
			continue
		}
		forgotten, skipped, failed := &result.Forgotten, &result.Skipped, &result.Failed
		if e.id == "" {
			forgotten, skipped, failed = &result.LegacyStems.Forgotten, &result.LegacyStems.Skipped, &result.LegacyStems.Failed
		}
		removed, held, err := s.sweepOne(e, now, ttl)
		switch {
		case err != nil:
			*failed = append(*failed, e.name())
			failures = append(failures, err)
			done++
		case !held:
			*skipped = append(*skipped, e.name())
		case removed:
			*forgotten = append(*forgotten, e.name())
			done++
		}
	}
	return result, errors.Join(failures...)
}

// sweepOne removes one store if it is still expired once its lock is
// held. held is false when another process holds the lock.
func (s *FileStore) sweepOne(e entry, now time.Time, ttl time.Duration) (removed, held bool, err error) {
	release, held, err := tryLock(e.loc.lockPath())
	if err != nil || !held {
		return false, held, err
	}
	defer release()
	sweepLocked(e.name())
	if !expired(e.loc, now, ttl) {
		return false, true, nil
	}
	if err := s.removeLocked(e.loc); err != nil {
		return false, true, err
	}
	return true, true, nil
}

// expired reports whether the location's newest file was last used more
// than ttl before now. A location with no file left is not expired.
func expired(l loc, now time.Time, ttl time.Duration) bool {
	var last time.Time
	found := false
	for _, path := range []string{l.agePath(), l.v1Path()} {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			found = true
			if info.ModTime().After(last) {
				last = info.ModTime()
			}
		}
	}
	return found && now.Sub(last) > ttl
}

// Find lists the sessions whose store holds any of values (the canonical
// forms of one value, as detection keys it), sorted by session, for a
// data subject's access or erasure request (GDPR arts. 15 and 17), then
// the legacy stems that hold them (see Holding).
//
// It decrypts every session and checks every entry with no early exit, so
// its duration depends on the store's size, not on whether or where a
// value is. It only reads: no file is migrated and no key is generated.
// It fails closed: a session it cannot read (missing or wrong key,
// corrupt file, a file name veil cannot map back to a session id) aborts
// the whole search with no partial answer, since an incomplete answer to
// such a request is worse than none.
func (s *FileStore) Find(values []string) ([]Holding, error) {
	want := make(map[string]struct{}, len(values))
	for _, v := range values {
		want[v] = struct{}{}
	}
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}

	holdings := []Holding{}
	index := map[string]int{} // a session met twice (a migration cut short) is one holding
	for _, e := range entries {
		data, err := s.peek(e.loc)
		if err != nil {
			return nil, err
		}
		categories := map[string]struct{}{}
		for key := range data.Mapping {
			category, original, _ := strings.Cut(key, ":")
			if _, ok := want[original]; ok {
				categories[category] = struct{}{}
			}
		}
		if len(categories) == 0 {
			continue
		}
		key := "legacy:" + e.loc.stem
		h := Holding{LegacyStem: e.loc.stem}
		if e.id != "" {
			key, h = "session:"+e.id, Holding{Session: e.id}
		}
		if i, ok := index[key]; ok {
			for _, c := range holdings[i].Categories {
				categories[c] = struct{}{}
			}
			h = holdings[i]
		} else {
			index[key] = len(holdings)
			holdings = append(holdings, h)
		}
		h.Categories = make([]string, 0, len(categories))
		for c := range categories {
			h.Categories = append(h.Categories, c)
		}
		sort.Strings(h.Categories)
		holdings[index[key]] = h
	}
	return holdings, nil
}

// entries lists every store with a mapping file (v2 age or v1 plaintext):
// the current ones in the ids directory, sorted by session id, then the
// legacy ones in the store directory, sorted by stem. A legacy stem only
// one session id can have produced is that session id; an ambiguous one
// has none. A current file whose stem veil cannot map back to a session
// id fails closed (ErrCorrupt). A missing directory has none.
func (s *FileStore) entries() ([]entry, error) {
	legacy, err := s.stems(s.dir)
	if err != nil {
		return nil, err
	}
	current, err := s.stems(s.idsPath())
	if err != nil {
		return nil, err
	}

	var out []entry
	for _, stem := range current {
		id, ok := s.idOf(stem)
		if !ok {
			return nil, fmt.Errorf("%w: a store file name maps to no session id", ErrCorrupt)
		}
		stem, hashed := encodeStem(id)
		out = append(out, entry{loc: loc{dir: s.idsPath(), stem: stem, id: id, hashed: hashed}, id: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	for _, stem := range legacy {
		e := entry{loc: s.legacyAt(stem)}
		if !ambiguousLegacy(stem) {
			e.id = stem
		}
		out = append(out, e)
	}
	return out, nil
}

// stems lists the stems of the mapping files (age or v1) in dir, sorted.
func (s *FileStore) stems(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pseudonymstore: list sessions: %w", err)
	}
	if err := securePrivateDir(dir); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var stems []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		stem, ok := strings.CutSuffix(name, ".age")
		if !ok {
			stem, ok = strings.CutSuffix(name, ".json")
		}
		if !ok || stem == "" || seen[stem] {
			continue
		}
		seen[stem] = true
		stems = append(stems, stem)
	}
	sort.Strings(stems)
	return stems, nil
}
