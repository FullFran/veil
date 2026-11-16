//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package pseudonymstore

import "os"

// Without a kernel lock this falls back to a create-exclusive lock file:
// a crash leaves it behind and the session reports ErrLocked until the
// file is removed by hand.
const lockOpenFlags = os.O_CREATE | os.O_EXCL | os.O_WRONLY

func lockFile(f *os.File) (bool, error) { return true, nil }

func releaseLock(f *os.File, path string) {
	f.Close()
	os.Remove(path)
}
