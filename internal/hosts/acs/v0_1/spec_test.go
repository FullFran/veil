package v0_1

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendoredSpec_MatchesSHA256SUMS is the pin: every vendored ACS file
// has the digest recorded in spec/SHA256SUMS, and no file is vendored
// without one. An ACS change shows up here as a failing pin bump, never as
// silent drift.
func TestVendoredSpec_MatchesSHA256SUMS(t *testing.T) {
	sums, err := os.Open(filepath.Join("spec", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer sums.Close()

	listed := map[string]bool{}
	scanner := bufio.NewScanner(sums)
	for scanner.Scan() {
		want, name, ok := strings.Cut(scanner.Text(), "  ")
		if !ok {
			t.Fatalf("malformed SHA256SUMS line %q", scanner.Text())
		}
		raw, err := os.ReadFile(filepath.Join("spec", filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%s: sha256 %x, want %s", name, got, want)
		}
		listed[name] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(listed) == 0 {
		t.Fatal("SHA256SUMS lists no file")
	}

	err = filepath.WalkDir("spec", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("spec", path)
		rel = filepath.ToSlash(rel)
		if rel == "SHA256SUMS" || rel == "SOURCE.md" {
			return nil
		}
		if !listed[rel] {
			t.Errorf("%s is vendored but has no digest in SHA256SUMS", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestVendoredSpec_ExamplesValidateAgainstTheirSchema checks the vendored
// examples against the vendored schemas: a request against the request
// envelope and its hook's payload schema, a response against the response
// envelope. It anchors the validator to the spec's own messages.
func TestVendoredSpec_ExamplesValidateAgainstTheirSchema(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("spec", "examples"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			raw := readExample(t, e.Name())
			switch {
			case strings.HasSuffix(e.Name(), ".request.json"):
				if f := validateRequest(raw); f != nil {
					t.Fatalf("request does not validate: %v", f)
				}
			case strings.HasSuffix(e.Name(), ".response.json"):
				if err := validateResponse(raw); err != nil {
					t.Fatalf("response does not validate: %v", err)
				}
			default:
				t.Fatalf("example %s is neither a request nor a response", e.Name())
			}
		})
	}
}

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("spec", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
