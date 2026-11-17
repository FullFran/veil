package ner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FullFran/veil/internal/ner"
)

// modelServer serves files by path over TLS and counts requests.
type modelServer struct {
	*httptest.Server
	files map[string][]byte
	hits  atomic.Int32
}

func newModelServer(t *testing.T, files map[string][]byte) *modelServer {
	t.Helper()
	s := &modelServer{files: files}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		body, ok := s.files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// entryFor is a catalog entry whose files are content, served by s.
func entryFor(t *testing.T, s *modelServer, content map[string][]byte) ner.Entry {
	t.Helper()
	e := validEntry()
	var files []any
	for _, path := range []string{"config.json", "weights/model.bin"} {
		body := content[path]
		files = append(files, map[string]any{"path": path, "url": s.URL + "/" + path, "size": len(body), "digest": sha(body)})
	}
	e["files"] = files
	c, err := ner.ParseCatalog(catalogDoc(t, e))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := c.Lookup("test-model")
	return entry
}

var testFiles = map[string][]byte{"config.json": []byte(`{"a":1}`), "weights/model.bin": []byte("0123456789")}

func TestPull_DownloadsAndVerifies(t *testing.T) {
	s := newModelServer(t, testFiles)
	entry := entryFor(t, s, testFiles)
	dir := ner.ModelDir(t.TempDir(), entry)

	if err := ner.Pull(context.Background(), s.Client(), dir, entry); err != nil {
		t.Fatal(err)
	}
	for path, want := range testFiles {
		got, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	if err := ner.Verify(dir, entry); err != nil {
		t.Fatalf("Verify after Pull: %v", err)
	}
	hits := s.hits.Load()
	if err := ner.Pull(context.Background(), s.Client(), dir, entry); err != nil || s.hits.Load() != hits {
		t.Fatalf("second Pull: err %v, %d new requests; want none", err, s.hits.Load()-hits)
	}
}

func TestPull_RejectsWrongContentAndLeavesNothing(t *testing.T) {
	cases := map[string]struct {
		served map[string][]byte
		want   error
	}{
		"other bytes": {map[string][]byte{"config.json": []byte(`{"a":2}`), "weights/model.bin": testFiles["weights/model.bin"]}, ner.ErrDigestMismatch},
		"too long":    {map[string][]byte{"config.json": []byte(`{"a":1}   `), "weights/model.bin": testFiles["weights/model.bin"]}, ner.ErrDigestMismatch},
		"too short":   {map[string][]byte{"config.json": []byte(`{}`), "weights/model.bin": testFiles["weights/model.bin"]}, ner.ErrDigestMismatch},
		"not found":   {map[string][]byte{"weights/model.bin": testFiles["weights/model.bin"]}, ner.ErrDownload},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newModelServer(t, tc.served)
			entry := entryFor(t, s, testFiles)
			root := t.TempDir()
			dir := ner.ModelDir(root, entry)

			if err := ner.Pull(context.Background(), s.Client(), dir, entry); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(dir, "config.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("config.json exists after a failed pull (stat err %v)", err)
			}
			leftovers, _ := filepath.Glob(filepath.Join(dir, ".partial", "*"))
			if len(leftovers) > 0 {
				t.Fatalf("temporary files left: %v", leftovers)
			}
		})
	}
}

func TestPull_RefusesARedirectAwayFromHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(testFiles["config.json"]) }))
	t.Cleanup(plain.Close)
	s := newModelServer(t, testFiles)
	s.Config.Handler = http.RedirectHandler(plain.URL+"/config.json", http.StatusFound)
	entry := entryFor(t, s, testFiles)

	client := ner.HTTPClient()
	client.Transport = s.Client().Transport
	if err := ner.Pull(context.Background(), client, ner.ModelDir(t.TempDir(), entry), entry); !errors.Is(err, ner.ErrDownload) {
		t.Fatalf("err = %v, want ErrDownload", err)
	}
}

func TestVerify_MissingAndTamperedFiles(t *testing.T) {
	s := newModelServer(t, testFiles)
	entry := entryFor(t, s, testFiles)
	dir := ner.ModelDir(t.TempDir(), entry)

	if err := ner.Verify(dir, entry); !errors.Is(err, ner.ErrModelMissing) {
		t.Fatalf("empty cache: err = %v, want ErrModelMissing", err)
	}
	if err := ner.Pull(context.Background(), s.Client(), dir, entry); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weights", "model.bin"), []byte("9876543210"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ner.Verify(dir, entry); !errors.Is(err, ner.ErrDigestMismatch) {
		t.Fatalf("tampered file: err = %v, want ErrDigestMismatch", err)
	}
	if ner.Present(dir, entry) != true {
		t.Fatal("Present checks sizes only; a same-size tampered file is present")
	}
	if err := os.Remove(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if ner.Present(dir, entry) {
		t.Fatal("Present with a file missing")
	}
}

func TestModelDir_IsUnderTheRootByIdAndRevision(t *testing.T) {
	s := newModelServer(t, testFiles)
	entry := entryFor(t, s, testFiles)
	if got, want := ner.ModelDir("/cache", entry), filepath.Join("/cache", entry.ID, entry.Source.Revision); got != want {
		t.Fatalf("ModelDir = %q, want %q", got, want)
	}
}

func TestCacheRoot_HonoursTheOverride(t *testing.T) {
	t.Setenv(ner.CacheEnvVar, "/somewhere/models")
	if root, err := ner.CacheRoot(); err != nil || root != "/somewhere/models" {
		t.Fatalf("CacheRoot = %q, %v", root, err)
	}
}

func TestAcceptLicense(t *testing.T) {
	e := ner.Entry{License: "GPL-3.0-only"}
	if err := ner.AcceptLicense(e, "GPL-3.0-only"); err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"", "GPL-3.0", "gpl-3.0-only", "GPL-3.0-or-later"} {
		if err := ner.AcceptLicense(e, other); !errors.Is(err, ner.ErrLicenseNotAccepted) {
			t.Fatalf("AcceptLicense(%q) = %v, want ErrLicenseNotAccepted", other, err)
		}
	}
}

// A catalog may name a file and the same name plus a suffix ("a" and
// "a.part"): downloading one must never write over the other.
func TestPull_TemporaryNameCannotBeACatalogFile(t *testing.T) {
	content := map[string][]byte{"a.part": []byte("first file"), "a": []byte("second file")}
	s := newModelServer(t, content)
	e := validEntry()
	var files []any
	for _, path := range []string{"a.part", "a"} {
		files = append(files, map[string]any{"path": path, "url": s.URL + "/" + path, "size": len(content[path]), "digest": sha(content[path])})
	}
	e["files"] = files
	c, err := ner.ParseCatalog(catalogDoc(t, e))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := c.Lookup("test-model")
	dir := ner.ModelDir(t.TempDir(), entry)

	if err := ner.Pull(context.Background(), s.Client(), dir, entry); err != nil {
		t.Fatal(err)
	}
	if err := ner.Verify(dir, entry); err != nil {
		t.Fatalf("Verify after Pull: %v", err)
	}
}
