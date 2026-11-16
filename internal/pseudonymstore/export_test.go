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
