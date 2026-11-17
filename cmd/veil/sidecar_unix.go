//go:build unix

package main

import (
	"os"
	"strconv"
	"syscall"
)

// closeInheritedDescriptors marks every open descriptor above stderr
// close-on-exec, so no child veil starts inherits one. Go opens its own
// that way; this covers the ones veil inherited from its parent.
func closeInheritedDescriptors() error {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return err
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		syscall.CloseOnExec(fd)
	}
	return nil
}
