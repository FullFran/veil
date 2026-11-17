package eval

// SetSlowdown makes Run time n Evaluate calls as one sample, simulating
// an n-fold regression in Evaluate. It returns a function that restores
// the previous factor. Tests that call it must not run in parallel.
func SetSlowdown(n int) (restore func()) {
	prev := slowdown
	slowdown = n
	return func() { slowdown = prev }
}
