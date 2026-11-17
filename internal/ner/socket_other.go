//go:build !unix

package ner

import "fmt"

// checkSocket fails closed where veil cannot check a socket's owner.
func checkSocket(string) error {
	return fmt.Errorf("%w: socket ownership cannot be checked on this platform", ErrUnavailable)
}
