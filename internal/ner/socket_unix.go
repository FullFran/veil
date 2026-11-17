//go:build unix

package ner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// checkSocket refuses a socket path another user could have put there or
// could replace: the path must be a socket itself (not a symlink to
// one), and both it and its directory must belong to veil's user and be
// writable by no one else. The sidecar's answers decide what is redacted,
// so they are only taken from a socket only this user controls.
func checkSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%w: %s is not a socket", ErrUnavailable, path)
	}
	if err := ownedAndPrivate(fi); err != nil {
		return fmt.Errorf("%w: socket %s %v", ErrUnavailable, path, err)
	}
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := ownedAndPrivate(di); err != nil {
		return fmt.Errorf("%w: directory %s %v", ErrUnavailable, dir, err)
	}
	return nil
}

func ownedAndPrivate(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("has no owner")
	}
	if uid := os.Getuid(); uid < 0 || uint64(st.Uid) != uint64(uid) {
		return fmt.Errorf("belongs to another user")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("is writable by group or others")
	}
	return nil
}
