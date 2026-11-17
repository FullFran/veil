package ner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

// CacheEnvVar overrides the model cache root.
const CacheEnvVar = "VEIL_MODEL_CACHE"

// Model cache failures. Callers branch with errors.Is.
var (
	// ErrModelMissing: a file of the model is not in the cache.
	ErrModelMissing = errors.New("ner: model not in the cache")
	// ErrDigestMismatch: a file's size or SHA-256 differs from its
	// catalog entry, in the cache or as downloaded.
	ErrDigestMismatch = errors.New("ner: model file does not match its digest")
	// ErrLicenseNotAccepted: the licence the operator accepted is not
	// exactly the model's SPDX id.
	ErrLicenseNotAccepted = errors.New("ner: model licence not accepted")
	// ErrDownload: a file could not be downloaded (network, HTTP status,
	// a redirect away from https, or the cache cannot be written).
	ErrDownload = errors.New("ner: model download failed")
)

// CacheRoot returns $VEIL_MODEL_CACHE, else <user cache dir>/veil/models.
func CacheRoot() (string, error) {
	if dir := os.Getenv(CacheEnvVar); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrModelMissing, err)
	}
	return filepath.Join(base, "veil", "models"), nil
}

// ModelDir is where entry's files live under root: <root>/<id>/<revision>.
// The schema keeps both one safe path segment.
func ModelDir(root string, e Entry) string {
	return filepath.Join(root, e.ID, e.Source.Revision)
}

// AcceptLicense succeeds only when accepted is exactly e's SPDX licence id.
func AcceptLicense(e Entry, accepted string) error {
	if accepted != e.License {
		return fmt.Errorf("%w: the model is %s", ErrLicenseNotAccepted, e.License)
	}
	return nil
}

// HTTPClient is the client Pull should use: it follows at most 10
// redirects and only to https URLs.
func HTTPClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		switch {
		case len(via) >= 10:
			return errors.New("too many redirects")
		case req.URL.Scheme != "https":
			return fmt.Errorf("redirect to a %s URL", req.URL.Scheme)
		}
		return nil
	}}
}

// Present reports whether every file of e is in dir with its declared
// size. It does not hash: Verify does.
func Present(dir string, e Entry) bool {
	for _, f := range e.Files {
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil || !info.Mode().IsRegular() || info.Size() != f.Size {
			return false
		}
	}
	return true
}

// Verify re-hashes every file of e in dir.
func Verify(dir string, e Entry) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrModelMissing, err)
	}
	defer func() { _ = root.Close() }()
	for _, f := range e.Files {
		if err := verifyFile(root, f); err != nil {
			return err
		}
	}
	return nil
}

func verifyFile(root *os.Root, f File) error {
	file, err := root.Open(filepath.FromSlash(f.Path))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrModelMissing, f.Path)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrModelMissing, err)
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, f.Size+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrModelMissing, err)
	}
	return checkDigest(f, n, h)
}

func checkDigest(f File, n int64, h hash.Hash) error {
	if n != f.Size {
		return fmt.Errorf("%w: %s has %d bytes, want %d", ErrDigestMismatch, f.Path, n, f.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != f.Digest {
		return fmt.Errorf("%w: %s", ErrDigestMismatch, f.Path)
	}
	return nil
}

// Pull downloads every file of e into dir that is not already there and
// verified. Each file is written to a temporary name, hashed while it is
// written, read up to one byte past its declared size, and renamed into
// place only when its size and digest match; otherwise it is removed.
func Pull(ctx context.Context, client *http.Client, dir string, e Entry) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	defer func() { _ = root.Close() }()
	for _, f := range e.Files {
		if verifyFile(root, f) == nil {
			continue
		}
		if err := download(ctx, client, root, f); err != nil {
			return err
		}
	}
	return nil
}

func download(ctx context.Context, client *http.Client, root *os.Root, f File) (err error) {
	name := filepath.FromSlash(f.Path)
	if parent := path.Dir(f.Path); parent != "." {
		if err := root.MkdirAll(filepath.FromSlash(parent), 0o700); err != nil {
			return fmt.Errorf("%w: %v", ErrDownload, err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	resp, err := client.Do(req) // #nosec G704 -- the URL is a pinned https catalog URL, the content is checked against its digest
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s: HTTP %d", ErrDownload, f.Path, resp.StatusCode)
	}

	part := name + ".part"
	out, err := root.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = root.Remove(part)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrDownload, f.Path, err)
	}
	if err = checkDigest(f, n, h); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	if err = root.Rename(part, name); err != nil {
		return fmt.Errorf("%w: %v", ErrDownload, err)
	}
	return nil
}
