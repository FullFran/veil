//go:build !unix

package pseudonymstore

// securePrivateDir is a no-op where POSIX owners and modes do not apply;
// the directory is created 0700 where they do.
func securePrivateDir(dir string) error { return nil }
