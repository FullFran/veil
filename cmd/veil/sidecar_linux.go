//go:build linux

package main

import "syscall"

// sidecarProcAttr has the kernel kill the sidecar when serve dies, even
// by SIGKILL, so a sidecar is never left running without its serve.
func sidecarProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
