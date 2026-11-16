//go:build unix

package pseudonymstore

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// securePrivateDir makes the sessions directory private before veil uses
// it. DefaultDir can fall back to a shared temp directory, where another
// user could have created it first: a directory owned by someone else
// fails closed, and one of ours that group or others can reach is
// tightened to 0700.
func securePrivateDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("pseudonymstore: stat dir: %w", err)
	}
	if !info.IsDir() {
		return &fs.PathError{Op: "check sessions dir", Path: dir, Err: syscall.ENOTDIR}
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return &fs.PathError{Op: "check sessions dir owner", Path: dir, Err: fs.ErrPermission}
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs the search bit; 0700 is owner-only
			return fmt.Errorf("pseudonymstore: tighten dir: %w", err)
		}
	}
	return nil
}
