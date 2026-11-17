package ner_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/ner"
)

// validEntry is a minimal entry the schema accepts; cases mutate a copy.
func validEntry() map[string]any {
	return map[string]any{
		"id":        "test-model",
		"runtime":   "gliner2",
		"source":    map[string]any{"repo": "example/model", "revision": strings.Repeat("c", 40)},
		"license":   "Apache-2.0",
		"languages": []any{"es"},
		"labels":    map[string]any{"person": "NOMBRE"},
		"files": []any{map[string]any{
			"path":   "model.safetensors",
			"url":    "https://example.org/model.safetensors",
			"size":   10,
			"digest": "sha256:" + strings.Repeat("d", 64),
		}},
	}
}

func catalogDoc(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	models := make([]any, len(entries))
	for i, e := range entries {
		models[i] = e
	}
	b, err := json.Marshal(map[string]any{"version": "1.0", "models": models})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEmbeddedCatalog_PinsTheBenchmarkedModels(t *testing.T) {
	c, err := ner.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	for id, revision := range map[string]string{
		"gliner2-pii":           "1cb4166094dc58fa8d836429f060d6c95f62b495",
		"spacy-es-core-news-lg": "es_core_news_lg-3.8.0",
	} {
		e, err := c.Lookup(id)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", id, err)
		}
		if e.Source.Revision != revision {
			t.Errorf("%s revision = %q, want %q", id, e.Source.Revision, revision)
		}
		if len(e.Files) == 0 || e.Labels == nil {
			t.Errorf("%s has no files or labels", id)
		}
	}
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	for _, e := range c.Entries() {
		for _, f := range e.Files {
			if !strings.HasPrefix(f.URL, "https://") || !digest.MatchString(f.Digest) || f.Size <= 0 {
				t.Errorf("%s/%s: url %q, digest %q, size %d", e.ID, f.Path, f.URL, f.Digest, f.Size)
			}
			if strings.Contains(f.URL, "huggingface.co") && !strings.Contains(f.URL, "/resolve/"+e.Source.Revision+"/") {
				t.Errorf("%s/%s: url %q does not resolve the pinned revision", e.ID, f.Path, f.URL)
			}
		}
	}
}

func TestCatalog_Lookup_UnknownModel(t *testing.T) {
	c, err := ner.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lookup("no-such-model"); !errors.Is(err, ner.ErrModelUnknown) {
		t.Fatalf("err = %v, want ErrModelUnknown", err)
	}
}

func TestParseCatalog_RejectsInvalidDocuments(t *testing.T) {
	with := func(mutate func(e map[string]any)) []byte {
		e := validEntry()
		mutate(e)
		return catalogDoc(t, e)
	}
	file := func(e map[string]any) map[string]any { return e["files"].([]any)[0].(map[string]any) }
	cases := map[string][]byte{
		"not JSON":         []byte(`{"version":`),
		"duplicate member": []byte(`{"version":"1.0","version":"1.0","models":[]}`),
		"other version":    []byte(`{"version":"2.0","models":[]}`),
		"unknown member":   with(func(e map[string]any) { e["extra"] = true }),
		"http url":         with(func(e map[string]any) { file(e)["url"] = "http://example.org/m" }),
		"bad digest":       with(func(e map[string]any) { file(e)["digest"] = "sha256:ABC" }),
		"no files":         with(func(e map[string]any) { e["files"] = []any{} }),
		"zero size":        with(func(e map[string]any) { file(e)["size"] = 0 }),
		"label category":   with(func(e map[string]any) { e["labels"] = map[string]any{"person": "DNI"} }),
		"no labels":        with(func(e map[string]any) { e["labels"] = map[string]any{} }),
		"empty revision":   with(func(e map[string]any) { e["source"].(map[string]any)["revision"] = "" }),
		"revision escapes": with(func(e map[string]any) { e["source"].(map[string]any)["revision"] = "../x" }),
		"path escapes":     with(func(e map[string]any) { file(e)["path"] = "../model.safetensors" }),
		"absolute path":    with(func(e map[string]any) { file(e)["path"] = "/etc/passwd" }),
		"dot segment":      with(func(e map[string]any) { file(e)["path"] = "a/./b" }),
		// The model cache keeps partial downloads under ".partial/", a name
		// no catalog path can take.
		"hidden segment": with(func(e map[string]any) { file(e)["path"] = ".partial/model.safetensors" }),
		"hidden file":    with(func(e map[string]any) { file(e)["path"] = "a/.b" }),
		"duplicate path": with(func(e map[string]any) {
			e["files"] = append(e["files"].([]any), file(e))
		}),
		"duplicate id": catalogDoc(t, validEntry(), validEntry()),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ner.ParseCatalog(raw); !errors.Is(err, ner.ErrCatalogInvalid) {
				t.Fatalf("err = %v, want ErrCatalogInvalid", err)
			}
		})
	}
}

func writeCatalog(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "models.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCatalog_UserCatalogAddsEntries(t *testing.T) {
	c, err := ner.LoadCatalog(writeCatalog(t, catalogDoc(t, validEntry())))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lookup("test-model"); err != nil {
		t.Fatalf("user entry: %v", err)
	}
	if _, err := c.Lookup("gliner2-pii"); err != nil {
		t.Fatalf("embedded entry next to a user catalog: %v", err)
	}
}

func TestLoadCatalog_UserCatalogCannotShadowAnEmbeddedEntry(t *testing.T) {
	e := validEntry()
	e["id"] = "gliner2-pii"
	if _, err := ner.LoadCatalog(writeCatalog(t, catalogDoc(t, e))); !errors.Is(err, ner.ErrCatalogInvalid) {
		t.Fatalf("err = %v, want ErrCatalogInvalid", err)
	}
}

func TestLoadCatalog_UnreadableUserCatalog(t *testing.T) {
	if _, err := ner.LoadCatalog(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, ner.ErrCatalogInvalid) {
		t.Fatalf("err = %v, want ErrCatalogInvalid", err)
	}
}

func TestEntry_DigestIdentifiesTheEntry(t *testing.T) {
	c, err := ner.ParseCatalog(catalogDoc(t, validEntry()))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := c.Lookup("test-model")
	sum := sha256.Sum256(e.Canonical())
	if e.Digest() != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("Digest() = %s, want sha256 of Canonical()", e.Digest())
	}
	if m := e.Model(); m.ID != e.ID || m.Revision != e.Source.Revision || m.EntryDigest != e.Digest() {
		t.Fatalf("Model() = %+v, want id, revision and entry digest", m)
	}

	changed := validEntry()
	changed["parameters"] = map[string]any{"threshold": 0.7}
	c2, err := ner.ParseCatalog(catalogDoc(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := c2.Lookup("test-model")
	if e2.Digest() == e.Digest() {
		t.Fatal("changing a parameter kept the entry digest")
	}

	// The same entry written with other member order and spacing has the
	// same digest: it identifies content, not formatting.
	reordered := []byte(`{"models":[{"files":[{"digest":"sha256:` + strings.Repeat("d", 64) + `","size":10,"url":"https://example.org/model.safetensors","path":"model.safetensors"}],
	  "labels":{"person":"NOMBRE"},"languages":["es"],"license":"Apache-2.0",
	  "source":{"revision":"` + strings.Repeat("c", 40) + `","repo":"example/model"},"runtime":"gliner2","id":"test-model"}],"version":"1.0"}`)
	c3, err := ner.ParseCatalog(reordered)
	if err != nil {
		t.Fatal(err)
	}
	e3, _ := c3.Lookup("test-model")
	if e3.Digest() != e.Digest() {
		t.Fatal("member order changed the entry digest")
	}
}
