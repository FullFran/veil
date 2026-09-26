package domain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestNameCatalogDetector_WholeWordCaseAccentInsensitive_IsDetected proves
// a catalog name fires on the exact form, a different case, and a
// stripped-accent form, but not as a substring of an unrelated word.
func TestNameCatalogDetector_WholeWordCaseAccentInsensitive_IsDetected(t *testing.T) {
	d := domain.NewNameCatalogDetector([]string{"María Pérez", "Muñoz"})

	cases := []struct {
		name string
		text string
		want string
	}{
		{"exact form", "please call María Pérez about the invoice", "María Pérez"},
		{"different case", "PLEASE CALL MARIA PEREZ ABOUT THE INVOICE", "MARIA PEREZ"},
		{"accent stripped", "please call maria perez about the invoice", "maria perez"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := d.Detect(domain.Event{Kind: domain.EventPromptSubmit, Text: tc.text})
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			if findings[0].Match != tc.want {
				t.Errorf("Match = %q, want %q", findings[0].Match, tc.want)
			}
			if findings[0].Category != "NOMBRE" {
				t.Errorf("Category = %q, want %q", findings[0].Category, "NOMBRE")
			}
		})
	}
}

// TestNameCatalogDetector_SubstringInUnrelatedWord_IsIgnored proves the
// matcher respects whole-word boundaries: "Muñoz" must not fire inside
// "Munozville".
func TestNameCatalogDetector_SubstringInUnrelatedWord_IsIgnored(t *testing.T) {
	d := domain.NewNameCatalogDetector([]string{"Muñoz"})

	findings := d.Detect(domain.Event{Kind: domain.EventPromptSubmit, Text: "the town of Munozville has no relation"})
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

// TestLoadNameCatalog_JSONArray_IsParsed and the line-delimited variant
// below both write to t.TempDir(), never a real config directory.
func TestLoadNameCatalog_JSONArray_IsParsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	writeFile(t, path, `["María Pérez", "Muñoz"]`)

	names, err := domain.LoadNameCatalog(path)
	if err != nil {
		t.Fatalf("LoadNameCatalog returned unexpected error: %v", err)
	}
	if len(names) != 2 || names[0] != "María Pérez" || names[1] != "Muñoz" {
		t.Fatalf("got %v, want [María Pérez Muñoz]", names)
	}
}

func TestLoadNameCatalog_OneNamePerLine_IsParsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.txt")
	writeFile(t, path, "María Pérez\nMuñoz\n\n")

	names, err := domain.LoadNameCatalog(path)
	if err != nil {
		t.Fatalf("LoadNameCatalog returned unexpected error: %v", err)
	}
	if len(names) != 2 || names[0] != "María Pérez" || names[1] != "Muñoz" {
		t.Fatalf("got %v, want [María Pérez Muñoz]", names)
	}
}

func TestLoadNameCatalog_MissingFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := domain.LoadNameCatalog(filepath.Join(dir, "does-not-exist.json")); err == nil {
		t.Fatal("LoadNameCatalog returned no error for a missing file")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write test fixture %s: %v", path, err)
	}
}
