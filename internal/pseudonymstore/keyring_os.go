package pseudonymstore

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// OSKeyring is the Keyring backed by the operating system's secret store:
// the freedesktop Secret Service over D-Bus on Linux, the Keychain on
// macOS and the Credential Manager on Windows (github.com/zalando/go-keyring).
// Without a reachable secret store (for example a headless box with no
// D-Bus session) its calls return an error, which veil reports as
// VEIL_STORE_KEYRING_UNAVAILABLE.
type OSKeyring struct{}

// Get implements Keyring.
func (OSKeyring) Get(service, account string) (string, error) {
	secret, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrKeyringNotFound
	}
	return secret, err
}

// Set implements Keyring.
func (OSKeyring) Set(service, account, secret string) error {
	return keyring.Set(service, account, secret)
}
