package v0_1

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// signatureAlgorithm is the only ACS signature algorithm veil verifies:
// the v0.1 baseline (Specification section 10).
const signatureAlgorithm = "HMAC-SHA256"

// deriveKey derives the per-session HMAC key from the pre-shared secret:
// HKDF-SHA256 with no salt, the session_id's UTF-8 bytes as info and a
// 32-byte output (Specification section 10).
func deriveKey(secret []byte, sessionID string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, sessionID, 32)
}

// mac returns the HMAC-SHA256 of canonical under key.
func mac(key, canonical []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(canonical)
	return h.Sum(nil)
}

// signatureValue is the base64 (standard alphabet, padded) form ACS
// carries a signature in.
func signatureValue(key, canonical []byte) string {
	return base64.StdEncoding.EncodeToString(mac(key, canonical))
}
