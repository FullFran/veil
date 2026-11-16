package pseudonymstore

import (
	"fmt"
	"os"
	"time"
)

// lockWait bounds how long a session operation waits for the lock.
const lockWait = 2 * time.Second

// acquireLock takes the session lock at path, retrying briefly on
// contention, and returns a function that releases it. It fails closed
// with ErrLocked rather than blocking forever, since a held lock must
// surface as a blocked event, not a silently skipped rewrite.
//
// Where the OS has a kernel lock (flock on Unix, LockFileEx on Windows)
// the lock is that, on the file at path: the kernel releases it when the
// holder dies, so a crash never leaves a session locked forever, and a
// lock file with no holder (left by a crash, or by an older veil that
// used a create-exclusive file) is simply taken over.
func acquireLock(path string) (release func(), err error) {
	deadline := time.Now().Add(lockWait)
	for {
		release, held, err := tryLock(path)
		if err != nil {
			return nil, err
		}
		if held {
			return release, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: timed out waiting for %s", ErrLocked, path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// tryLock makes one attempt at the session lock at path, without waiting.
// held is false when another process holds it.
func tryLock(path string) (release func(), held bool, err error) {
	// A holder unlinks the file on release, so the file this attempt
	// locked can be gone from path by the time the lock is granted. Such
	// a lock guards nothing; retry on the file now at path. Bounded,
	// since each retry means another process made progress.
	for range 16 {
		f, err := os.OpenFile(path, lockOpenFlags, 0o600)
		if os.IsExist(err) {
			return nil, false, nil // create-exclusive fallback: held
		}
		if err != nil {
			return nil, false, fmt.Errorf("pseudonymstore: acquire lock: %w", err)
		}
		held, err := lockFile(f)
		if err != nil {
			f.Close()
			return nil, false, fmt.Errorf("pseudonymstore: acquire lock: %w", err)
		}
		if !held {
			f.Close()
			return nil, false, nil
		}
		if lockedFileIsAt(f, path) {
			return func() { releaseLock(f, path) }, true, nil
		}
		f.Close()
	}
	return nil, false, nil
}

// lockedFileIsAt reports whether f is still the file at path.
func lockedFileIsAt(f *os.File, path string) bool {
	held, err := f.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && os.SameFile(held, current)
}
