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
	Token(sessionID, category, original string) (string, error)
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
	mapping  map[string]string
	counters map[string]int
}

// NewMemoryPseudonymStore builds an empty MemoryPseudonymStore.
func NewMemoryPseudonymStore() *MemoryPseudonymStore {
	return &MemoryPseudonymStore{sessions: make(map[string]*sessionPseudonyms)}
}

// Token returns the stable pseudonym token for original within category
// and sessionID, minting "[category-NNN]" on first sight.
func (s *MemoryPseudonymStore) Token(sessionID, category, original string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		session = &sessionPseudonyms{mapping: make(map[string]string), counters: make(map[string]int)}
		s.sessions[sessionID] = session
	}

	key := category + ":" + original
	if token, ok := session.mapping[key]; ok {
		return token, nil
	}

	session.counters[category]++
	token := fmt.Sprintf("[%s-%03d]", category, session.counters[category])
	session.mapping[key] = token
	return token, nil
}
