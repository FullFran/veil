// Package docs_test keeps docs/threat-model.md honest: every claim the
// threat model makes about a test, a status or a code location is checked
// against the repository, so the document fails CI when it drifts.
package docs_test

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	threatModel = "threat-model.md"
	repoRoot    = ".."
)

// row is one threat row of a table that has a Status column.
type row struct {
	line   int
	id     string
	cells  map[string]string
	header []string
}

var (
	backticked = regexp.MustCompile("`([^`]+)`")
	issueRef   = regexp.MustCompile(`#\d+`)
	// codeRef is a mitigation reference: `path/to/file.ext` followed by the
	// symbol or text it points at, (`symbol`). It names no line number, so
	// unrelated edits to the file never make the document stale.
	codeRef = regexp.MustCompile("`([A-Za-z0-9_./-]+\\.[A-Za-z0-9]+)` \\(`([^`]+)`\\)")
	goTest  = regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`)
	jsTest  = regexp.MustCompile(`(?m)\btest\(\s*"([^"]+)"`)
)

var statuses = map[string]bool{"mitigated": true, "accepted": true, "open": true}

// threatRows returns the rows of every table in the document whose header
// has a Status column (the LINDDUN and STRIDE tables).
func threatRows(t *testing.T) []row {
	t.Helper()
	f, err := os.Open(threatModel)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var rows []row
	var header []string
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		n++
		line := sc.Text()
		if !strings.HasPrefix(line, "|") {
			header = nil
			continue
		}
		cells := splitRow(line)
		switch {
		case header == nil:
			header = cells
		case strings.HasPrefix(cells[0], "---"):
		case contains(header, "Status"):
			r := row{line: n, id: cells[0], cells: map[string]string{}, header: header}
			for i, name := range header {
				if i < len(cells) {
					r.cells[name] = cells[i]
				}
			}
			rows = append(rows, r)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no threat rows found")
	}
	return rows
}

// splitRow splits a Markdown table row into trimmed cells. Cells in this
// document never contain a literal pipe.
func splitRow(line string) []string {
	parts := strings.Split(strings.Trim(line, "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// repoTests returns every Go test function and every JS test name in the
// repository.
func repoTests(t *testing.T) map[string]bool {
	t.Helper()
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// Walking root.FS() keeps every read inside the repository, even through
	// a symlink.
	repo := root.FS()
	names := map[string]bool{}
	err = fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if base := d.Name(); base == ".git" || base == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		var re *regexp.Regexp
		switch {
		case strings.HasSuffix(path, "_test.go"):
			re = goTest
		case strings.HasSuffix(path, ".test.mjs"), strings.HasSuffix(path, ".test.js"):
			re = jsTest
		default:
			return nil
		}
		raw, err := fs.ReadFile(repo, path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
			names[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// TestThreatModel_EveryNamedTestExists fails when a test the document
// cites as proof is not a Go test function or a JS test in the repository.
func TestThreatModel_EveryNamedTestExists(t *testing.T) {
	tests := repoTests(t)
	for _, r := range threatRows(t) {
		for _, m := range backticked.FindAllStringSubmatch(r.cells["Test"], -1) {
			if !tests[m[1]] {
				t.Errorf("line %d, %s: test %q does not exist in any Go or JS test file", r.line, r.id, m[1])
			}
		}
	}
}

// TestThreatModel_StatusesAreMitigatedAcceptedOrOpen checks each row's
// status and what that status requires: a mitigated row names a test, an
// accepted row gives a reason, an open row links an issue.
func TestThreatModel_StatusesAreMitigatedAcceptedOrOpen(t *testing.T) {
	ids := map[string]int{}
	for _, r := range threatRows(t) {
		if prev, dup := ids[r.id]; dup {
			t.Errorf("line %d: ID %s already used on line %d", r.line, r.id, prev)
		}
		ids[r.id] = r.line

		status := r.cells["Status"]
		kind, reason, _ := strings.Cut(status, ":")
		if !statuses[kind] {
			t.Errorf("line %d, %s: status %q is not mitigated, accepted or open", r.line, r.id, status)
			continue
		}
		named := backticked.MatchString(r.cells["Test"])
		switch kind {
		case "mitigated":
			if !named {
				t.Errorf("line %d, %s: mitigated row names no test", r.line, r.id)
			}
		case "accepted":
			if strings.TrimSpace(reason) == "" {
				t.Errorf("line %d, %s: accepted row gives no reason", r.line, r.id)
			}
		case "open":
			if !issueRef.MatchString(reason) {
				t.Errorf("line %d, %s: open row links no issue", r.line, r.id)
			}
		}
		if !named && r.cells["Test"] != "none" {
			t.Errorf("line %d, %s: a row without a test says so with \"none\", got %q", r.line, r.id, r.cells["Test"])
		}
	}
}

// TestThreatModel_CodeReferencesPointAtTheirSymbol fails when a
// mitigation's file is gone or no longer contains the symbol it names.
func TestThreatModel_CodeReferencesPointAtTheirSymbol(t *testing.T) {
	seen := 0
	for _, r := range threatRows(t) {
		for _, m := range codeRef.FindAllStringSubmatch(r.cells["Mitigation"], -1) {
			seen++
			path, symbol := m[1], m[2]
			raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(path)))
			if err != nil {
				t.Errorf("line %d, %s: %s: %v", r.line, r.id, path, err)
				continue
			}
			if !strings.Contains(string(raw), symbol) {
				t.Errorf("line %d, %s: %s no longer contains %q", r.line, r.id, path, symbol)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no code reference found")
	}
}

// TestThreatModel_MapsTheRequiredRequirements fails when a requirement the
// threat model must map (issue #12) is not mapped by any threat row.
func TestThreatModel_MapsTheRequiredRequirements(t *testing.T) {
	var mapped strings.Builder
	for _, r := range threatRows(t) {
		mapped.WriteString(r.cells["Maps to"])
		mapped.WriteString(" ; ")
	}
	got := mapped.String()
	required := []string{
		"HCS-0005-R010", "R011", "R012", "R013", "R014", "R015",
		"HCS-0006", "HCS-0008-R011", "HCS-0008-R012", "HCS-0008-R019", "HCS-0008-R020",
		"GDPR 5(1)(c)", "5(1)(e)", "15", "17", "25", "32",
	}
	for _, id := range required {
		if !strings.Contains(got, id) {
			t.Errorf("no threat row maps %s", id)
		}
	}
}
