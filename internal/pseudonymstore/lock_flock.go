//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package pseudonymstore

import (
	"errors"
	"os"
	"syscall"
)

// lockOpenFlags never follows a symlink planted at the lock path.
const lockOpenFlags = os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW

// lockFile takes an exclusive flock(2) on f without blocking. flock locks
// belong to the open file description, so they exclude other descriptors
// even within one process, and the kernel drops them when the holder
// exits for any reason.
func lockFile(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

// releaseLock unlinks the lock file while still holding it, then drops
// the lock by closing it. Unlinking first is what keeps two writers out:
// a process that opened the old file before the unlink finds, once it
// gets the lock, that the file is no longer at the path (lockedFileIsAt)
// and retries on a fresh one.
func releaseLock(f *os.File, path string) {
	os.Remove(path)
	f.Close()
}
