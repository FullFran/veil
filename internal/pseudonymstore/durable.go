package pseudonymstore

import "os"

// syncFile and syncDir flush a file's data and a directory's entries to
// stable storage. They are variables only so tests can make them fail.
var (
	syncFile = func(f *os.File) error { return f.Sync() }
	syncDir  = func(dir string) error {
		d, err := os.Open(dir) // #nosec G304 -- the store's own sessions directory, opened only to fsync it
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
)
