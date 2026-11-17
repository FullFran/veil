package domain

import (
	"fmt"
	"sync"
)

// PseudonymStore assigns a stable pseudonym token to an original sensitive
// value, scoped to one session: the same original always maps to the same
// token within a session, and different sessions never share a mapping or
// a counter. Implementations must never leak the original value anywhere
// but the token's own in-memory or on-disk mapping, and must never send it
// to a model.
//
// Token must return an error rather than a zero-value token on any
// storage failure. Policy treats that as fail-closed: a Rewrite decision
// is only ever built from a token Token actually returned, never from a
// guess that might collide with (or fail to match) a previous mapping.
type PseudonymStore interface {
	// TokenFor returns the session's token for key (the canonical value
	// that identifies it, e.g. "+34612345678" or "12345678Z") in
	// category, minting the next "[category-NNN]" on first sight. written
	// is the value as it appeared in the text ("612 345 678"); the first
	// written form seen when the token is minted is what Original gives
	// back, so a rehydrated value matches the bytes the model was shown a
	// token for. A later sighting never changes it: a token never changes
	// meaning within a session.
	TokenFor(sessionID, category, key, written string) (string, error)
	// Token is TokenFor with the value written as its key.
	Token(sessionID, category, original string) (string, error)
	// Original reverses a token this session previously minted, back to
	// its first written form (its key, for a token minted without one): the rehydration step for a tool call that
	// writes real data to disk needs the real value, not the pseudonym
	// the model was shown. found is false (with a nil error) for a token
	// this session never minted; it is not itself a failure. A non-nil
	// error means the lookup itself failed (e.g. a corrupted store) and
	// must be treated as fail-closed by the caller.
	Original(sessionID, token string) (original string, found bool, err error)
}

// MemoryPseudonymStore is an in-process PseudonymStore. It is correct for
// as long as the process lives, but every OpenCode event is handled by a
// fresh `veil opencode` process (the shim spawns the binary per hook
// call), so a MemoryPseudonymStore built inside cmd/veil would never
// survive past the single event it was created for and would remint every
// pseudonym from scratch on every call. It exists here as the reference
// implementation of the PseudonymStore contract and for tests; production
// wiring for OpenCode uses the file-backed store in
// internal/pseudonymstore instead. See that package's doc comment for the
// full reasoning.
type MemoryPseudonymStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionPseudonyms
}

type sessionPseudonyms struct {
	mapping  map[string]string // "category:original" -> token
	reverse  map[string]string // token -> original
	written  map[string]string // token -> first written form, when it differs from the key
	counters map[string]int
}

// WrittenForm is what a store keeps beside a token's key when it mints
// the token: the written form, or "" when it is the key itself (nothing
// more to keep). Every PseudonymStore uses it with Rehydrated, so a token
// minted without a written form (a store written before written forms
// existed) rehydrates to its key.
func WrittenForm(key, written string) string {
	if written == key {
		return ""
	}
	return written
}

// Rehydrated is what a token rehydrates to: its first written form, or its
// key when none was kept.
func Rehydrated(key, written string) string {
	if written != "" {
		return written
	}
	return key
}

// NewMemoryPseudonymStore builds an empty MemoryPseudonymStore.
func NewMemoryPseudonymStore() *MemoryPseudonymStore {
	return &MemoryPseudonymStore{sessions: make(map[string]*sessionPseudonyms)}
}

// Token returns the stable pseudonym token for original within category
// and sessionID, minting "[category-NNN]" on first sight.
func (s *MemoryPseudonymStore) Token(sessionID, category, original string) (string, error) {
	return s.TokenFor(sessionID, category, original, original)
}

// TokenFor implements PseudonymStore.TokenFor.
func (s *MemoryPseudonymStore) TokenFor(sessionID, category, original, written string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		session = &sessionPseudonyms{mapping: make(map[string]string), reverse: make(map[string]string), written: make(map[string]string), counters: make(map[string]int)}
		s.sessions[sessionID] = session
	}

	key := category + ":" + original
	if token, ok := session.mapping[key]; ok {
		return token, nil
	}

	session.counters[category]++
	token := fmt.Sprintf("[%s-%03d]", category, session.counters[category])
	session.mapping[key] = token
	session.reverse[token] = original
	if w := WrittenForm(original, written); w != "" {
		session.written[token] = w
	}
	return token, nil
}

// Original implements domain.PseudonymStore's reverse lookup.
func (s *MemoryPseudonymStore) Original(sessionID, token string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return "", false, nil
	}
	original, found := session.reverse[token]
	return Rehydrated(original, session.written[token]), found, nil
}
