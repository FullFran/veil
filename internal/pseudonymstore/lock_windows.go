//go:build windows

package pseudonymstore

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const lockOpenFlags = os.O_CREATE | os.O_RDWR

// lockFile takes an exclusive LockFileEx lock on f without blocking. The
// system releases it when the holder's handle closes, including when the
// process dies.
func lockFile(f *os.File) (bool, error) {
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}

// releaseLock closes the lock file and leaves it in place: Windows cannot
// unlink an open file here, and an empty lock file holds no data.
func releaseLock(f *os.File, path string) { f.Close() }
