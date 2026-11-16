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
}

// Holding is one session whose store holds a searched value: the session
// id and the categories the value was pseudonymized under, never a value.
type Holding struct {
	Session    string   `json:"session"`
	Categories []string `json:"categories"`
}

// Sweep removes every session unused for longer than ttl (GDPR art.
// 5(1)(e) storage limitation). A session's last use is its file's mtime
// (see FileStore), so the sweep needs no key: a lost key never blocks
// deletion. It never waits for and never removes a session another
// process holds locked; it re-checks the last use under the lock, since
// the holder may just have used the session, and deletes through
// removeLocked, the same path as Forget.
func (s *FileStore) Sweep(ttl time.Duration) (SweepResult, error) {
	result := SweepResult{Forgotten: []string{}, Skipped: []string{}}
	sessions, err := s.sessions()
	if err != nil {
		return result, err
	}
	now := s.now()
	for _, id := range sessions {
		if !s.expired(id, now, ttl) {
			continue
		}
		release, held, err := tryLock(s.lockPath(id))
		if err != nil {
			return result, err
		}
		if !held {
			result.Skipped = append(result.Skipped, id)
			continue
		}
		if s.expired(id, now, ttl) {
			err = s.removeLocked(id)
		}
		release()
		if err != nil {
			return result, err
		}
		result.Forgotten = append(result.Forgotten, id)
	}
	return result, nil
}

// expired reports whether the session's newest file was last used more
// than ttl before now. A session with no file left is not expired.
func (s *FileStore) expired(id string, now time.Time, ttl time.Duration) bool {
	var last time.Time
	found := false
	for _, path := range []string{s.agePath(id), s.legacyPath(id)} {
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
// data subject's access or erasure request (GDPR arts. 15 and 17).
//
// It decrypts every session and checks every entry with no early exit, so
// its duration depends on the store's size, not on whether or where a
// value is. It fails closed: a session it cannot read (missing or wrong
// key, corrupt file) aborts the whole search with no partial answer, since
// an incomplete answer to such a request is worse than none.
func (s *FileStore) Find(values []string) ([]Holding, error) {
	want := make(map[string]struct{}, len(values))
	for _, v := range values {
		want[v] = struct{}{}
	}
	sessions, err := s.sessions()
	if err != nil {
		return nil, err
	}

	holdings := []Holding{}
	for _, id := range sessions {
		data, err := s.load(id, false)
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
		h := Holding{Session: id, Categories: make([]string, 0, len(categories))}
		for c := range categories {
			h.Categories = append(h.Categories, c)
		}
		sort.Strings(h.Categories)
		holdings = append(holdings, h)
	}
	return holdings, nil
}

// sessions lists the ids of the sessions with a store file (v2 age or v1
// plaintext) in the store directory, sorted. A missing directory has none.
func (s *FileStore) sessions() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pseudonymstore: list sessions: %w", err)
	}
	if err := securePrivateDir(s.dir); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var ids []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		id, ok := strings.CutSuffix(name, ".age")
		if !ok {
			id, ok = strings.CutSuffix(name, ".json")
		}
		if !ok || id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
