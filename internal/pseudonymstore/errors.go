package pseudonymstore

import "errors"

// Sentinel errors the store wraps, so callers classify a failure with
// errors.Is and never by message. Every one fails closed: none falls back
// to plaintext or to a fresh mapping.
var (
	// ErrKeyMissing: no store key is available (no host key, no systemd
	// credential, and the keyring holds none for an existing store), or a
	// host set VEIL_KEY_FD but the descriptor gives no key.
	ErrKeyMissing = errors.New("pseudonymstore: store key missing")
	// ErrKeyInvalid: the key is not an age X25519 identity, or it does
	// not open the session file (wrong key).
	ErrKeyInvalid = errors.New("pseudonymstore: store key invalid")
	// ErrCorrupt: a session file (v2 age or v1 plaintext) cannot be
	// decrypted, authenticated or parsed.
	ErrCorrupt = errors.New("pseudonymstore: session file corrupt")
	// ErrKeyringUnavailable: the OS keyring cannot be reached.
	ErrKeyringUnavailable = errors.New("pseudonymstore: keyring unavailable")
	// ErrLocked: another process held the session lock past the deadline.
	ErrLocked = errors.New("pseudonymstore: session locked")
	// ErrSessionRetired: the session was removed when its marker counters
	// could not be read, so it can never mint again without risking a
	// repeated marker. The host must use a new session id.
	ErrSessionRetired = errors.New("pseudonymstore: session retired")
)
