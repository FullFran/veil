package pseudonymstore

import (
	"os"
	"testing"
)

// FailSync makes the file or directory fsync fail for one test.
func FailSync(t *testing.T, file, dir error) {
	t.Helper()
	prevFile, prevDir := syncFile, syncDir
	t.Cleanup(func() { syncFile, syncDir = prevFile, prevDir })
	syncFile = func(f *os.File) error {
		if file != nil {
			return file
		}
		return prevFile(f)
	}
	syncDir = func(d string) error {
		if dir != nil {
			return dir
		}
		return prevDir(d)
	}
}

// HoldLock takes the session lock at path, as another veil process
// would, until the test ends or release is called.
func HoldLock(t *testing.T, path string) (release func()) {
	t.Helper()
	release, err := acquireLock(path)
	if err != nil {
		t.Fatalf("HoldLock: %v", err)
	}
	t.Cleanup(release)
	return release
}

// OnSweepLocked runs f each time Sweep holds a session's lock, before it
// re-checks expiry, for the rest of the test.
func OnSweepLocked(t *testing.T, f func(sessionID string)) {
	prev := sweepLocked
	sweepLocked = f
	t.Cleanup(func() { sweepLocked = prev })
}

// CrashMigrationAfter makes a migration stop with err right after it
// moves the file with suffix, as a crash there would, for the rest of
// the test or until the returned function is called.
func CrashMigrationAfter(t *testing.T, suffix string, err error) (recover func()) {
	t.Helper()
	prev := migrateStep
	migrateStep = func(s string) error {
		if s == suffix {
			return err
		}
		return nil
	}
	recover = func() { migrateStep = prev }
	t.Cleanup(recover)
	return recover
}
