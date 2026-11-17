//go:build !unix

package main

// closeInheritedDescriptors has nothing to do: outside Unix a child
// inherits only the handles it is given.
func closeInheritedDescriptors() error { return nil }
