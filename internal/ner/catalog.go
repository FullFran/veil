package ner

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/FullFran/veil/internal/policy"
)

// CatalogEnvVar names an extra catalog file whose entries are added to
// the embedded ones.
const CatalogEnvVar = "VEIL_NER_CATALOG"

// maxCatalogBytes bounds a user catalog file.
const maxCatalogBytes = 1 << 20

// Catalog failures. Callers branch with errors.Is.
var (
	// ErrCatalogInvalid: a catalog is unreadable, not one JSON document
	// without duplicate members, does not match the schema, repeats an id
	// or a file path, or a user entry reuses an embedded id.
	ErrCatalogInvalid = errors.New("ner: model catalog invalid")
	// ErrModelUnknown: no catalog entry has the requested id.
	ErrModelUnknown = errors.New("ner: unknown model")
)

//go:embed catalog.json
var embeddedCatalog []byte

//go:embed catalog.schema.json
var catalogSchemaBytes []byte

// CatalogSchema returns the JSON Schema a catalog document must match.
func CatalogSchema() []byte { return bytes.Clone(catalogSchemaBytes) }

// Catalog is the set of models veil can select.
type Catalog struct {
	entries []Entry
}

// Entry is one pinned model: where its files come from, their sizes and
// digests, its licence and the labels veil asks it for.
type Entry struct {
	ID         string            `json:"id"`
	Runtime    string            `json:"runtime"`
	Source     Source            `json:"source"`
	License    string            `json:"license"`
	Languages  []string          `json:"languages"`
	Labels     map[string]string `json:"labels"`
	Parameters *Parameters       `json:"parameters,omitempty"`
	Files      []File            `json:"files"`
	Cost       *Cost             `json:"cost,omitempty"`
}

// Source is the upstream repository and the immutable revision pinned.
type Source struct {
	Repo     string `json:"repo"`
	Revision string `json:"revision"`
}

// Parameters tune the runtime.
type Parameters struct {
	Threshold *float64 `json:"threshold,omitempty"`
}

// File is one file of a model, relative to its model directory.
type File struct {
	Path   string `json:"path"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// Cost is what research/ner-benchmark measured; informative only.
type Cost struct {
	DiskMB     float64 `json:"diskMB,omitempty"`
	RSSMB      float64 `json:"rssMB,omitempty"`
	RSSPeakMB  float64 `json:"rssPeakMB,omitempty"`
	ColdStartS float64 `json:"coldStartS,omitempty"`
	P50Ms      float64 `json:"p50Ms,omitempty"`
	P95Ms      float64 `json:"p95Ms,omitempty"`
	MeasuredBy string  `json:"measuredBy,omitempty"`
}

// Canonical returns the entry as veil serializes it: struct member order,
// sorted label keys, no insignificant space. It is what the entry digest
// covers and what `veil model serve` hands the sidecar.
func (e Entry) Canonical() []byte {
	b, err := json.Marshal(e)
	if err != nil {
		panic(fmt.Sprintf("veil: marshal catalog entry: %v", err))
	}
	return b
}

// Digest is "sha256:" and the hex SHA-256 of Canonical.
func (e Entry) Digest() string {
	sum := sha256.Sum256(e.Canonical())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Model is what a sidecar serving this entry must report.
func (e Entry) Model() Model {
	return Model{ID: e.ID, Revision: e.Source.Revision, EntryDigest: e.Digest()}
}

// Entries returns every entry, embedded ones first, in file order.
func (c *Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

// Lookup returns the entry with id, or an error wrapping ErrModelUnknown.
func (c *Catalog) Lookup(id string) (Entry, error) {
	for _, e := range c.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("%w: %q", ErrModelUnknown, id)
}

// LoadCatalog returns the embedded catalog plus the entries of the
// catalog file at userPath, when it is not empty. A user entry never
// replaces an embedded one: reusing an id is an error.
func LoadCatalog(userPath string) (*Catalog, error) {
	c, err := ParseCatalog(embeddedCatalog)
	if err != nil {
		panic(fmt.Sprintf("veil: embedded model catalog is invalid: %v", err))
	}
	if userPath == "" {
		return c, nil
	}
	raw, err := readCatalog(userPath)
	if err != nil {
		return nil, err
	}
	user, err := ParseCatalog(raw)
	if err != nil {
		return nil, err
	}
	for _, e := range user.entries {
		if _, err := c.Lookup(e.ID); err == nil {
			return nil, fmt.Errorf("%w: %s reuses the embedded id %q", ErrCatalogInvalid, userPath, e.ID)
		}
		c.entries = append(c.entries, e)
	}
	return c, nil
}

func readCatalog(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator chooses the catalog file (VEIL_NER_CATALOG)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxCatalogBytes+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	case len(raw) > maxCatalogBytes:
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrCatalogInvalid, maxCatalogBytes)
	}
	return raw, nil
}

// ParseCatalog validates raw as one catalog document.
func ParseCatalog(raw []byte) (*Catalog, error) {
	if err := policy.RejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	}
	s, err := catalogSchema()
	if err != nil {
		return nil, fmt.Errorf("veil: compile embedded catalog schema: %w", err)
	}
	if err := s.Validate(instance); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	}
	var doc struct {
		Models []Entry `json:"models"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	}
	ids := map[string]bool{}
	for _, e := range doc.Models {
		if ids[e.ID] {
			return nil, fmt.Errorf("%w: id %q appears twice", ErrCatalogInvalid, e.ID)
		}
		ids[e.ID] = true
		paths := map[string]bool{}
		for _, f := range e.Files {
			if paths[f.Path] {
				return nil, fmt.Errorf("%w: %s lists %q twice", ErrCatalogInvalid, e.ID, f.Path)
			}
			paths[f.Path] = true
		}
	}
	return &Catalog{entries: doc.Models}, nil
}

var (
	schemaOnce     sync.Once
	compiledSchema *jsonschema.Schema
	schemaErr      error
)

func catalogSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(catalogSchemaBytes))
		if err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		const url = "urn:veil:schema:ner-catalog:1.0"
		if err := c.AddResource(url, doc); err != nil {
			schemaErr = err
			return
		}
		compiledSchema, schemaErr = c.Compile(url)
	})
	return compiledSchema, schemaErr
}
