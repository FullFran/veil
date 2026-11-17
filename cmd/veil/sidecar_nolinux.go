//go:build !linux

package main

import "syscall"

// sidecarProcAttr is the default: only Linux can tie the sidecar's life
// to serve's (Pdeathsig).
func sidecarProcAttr() *syscall.SysProcAttr { return nil }
