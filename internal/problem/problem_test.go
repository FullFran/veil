package problem

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wantCodes is every code veil defines. Adding a code means adding it
// here, to All() and to the README table; removing or renaming one breaks
// hosts that branch on it, so this list is deliberately spelled out.
var wantCodes = []Code{
	Usage,
	InputInvalid,
	CatalogUnreadable,
	PolicyUnreadable,
	PolicyInvalid,
	CapabilityUnsupported,
	StoreKeyMissing,
	StoreKeyInvalid,
	StoreCorrupt,
	StoreKeyringUnavailable,
	StoreLocked,
	SessionRetired,
	StoreIO,
	EvidenceWrite,
	CatalogRevisionInvalid,
	ACSVersionUnsupported,
	ACSRequestInvalid,
	ACSMethodUnsupported,
	ACSSignatureInvalid,
	ACSReplay,
	ACSTimestampOutOfWindow,
	ACSKeyInvalid,
	ACSUnredactable,
	Timeout,
	OutputTooLarge,
	Unavailable,
	Internal,
}

func TestAll_ListsEveryCodeOnce(t *testing.T) {
	got := All()
	if len(got) != len(wantCodes) {
		t.Fatalf("len(All()) = %d, want %d", len(got), len(wantCodes))
	}
	seen := map[Code]bool{}
	for _, c := range got {
		if seen[c] {
			t.Fatalf("code %s listed twice", c)
		}
		seen[c] = true
	}
	for _, c := range wantCodes {
		if !seen[c] {
			t.Fatalf("All() is missing %s", c)
		}
	}
}

func TestType_IsStableTagURIDerivedFromCode(t *testing.T) {
	cases := map[Code]string{
		Usage:           "tag:fullfran.github.io,2026:veil/problems/usage",
		StoreKeyMissing: "tag:fullfran.github.io,2026:veil/problems/store-key-missing",
		OutputTooLarge:  "tag:fullfran.github.io,2026:veil/problems/output-too-large",
	}
	for code, want := range cases {
		if got := code.Type(); got != want {
			t.Errorf("%s.Type() = %q, want %q", code, got, want)
		}
	}
	for _, c := range All() {
		if !strings.HasPrefix(c.Type(), TypeBase) {
			t.Errorf("%s.Type() = %q, want prefix %q", c, c.Type(), TypeBase)
		}
		if c.Title() == "" {
			t.Errorf("%s has no title", c)
		}
	}
}

func TestWrite_EmitsOneProblemJSONLineWithoutStatus(t *testing.T) {
	for _, code := range All() {
		var buf bytes.Buffer
		if err := Write(&buf, New(code)); err != nil {
			t.Fatalf("Write(%s): %v", code, err)
		}
		out := buf.String()
		if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
			t.Fatalf("Write(%s) = %q, want exactly one line", code, out)
		}
		var got map[string]any
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("Write(%s) is not JSON: %v", code, err)
		}
		if got["type"] != code.Type() || got["code"] != string(code) {
			t.Fatalf("Write(%s) = %v, want type %q and code %q", code, got, code.Type(), code)
		}
		if _, ok := got["title"].(string); !ok {
			t.Fatalf("Write(%s) has no title", code)
		}
		if _, ok := got["detail"].(string); !ok {
			t.Fatalf("Write(%s) has no detail", code)
		}
		if _, ok := got["status"]; ok {
			t.Fatalf("Write(%s) carries an HTTP status; the non-HTTP profile omits it", code)
		}
	}
}

func TestExitClasses(t *testing.T) {
	if ExitDecision != 0 || ExitFailedClosed != 1 || ExitUsage != 2 {
		t.Fatalf("exit classes = %d/%d/%d, want 0 decision, 1 failed closed, 2 usage", ExitDecision, ExitFailedClosed, ExitUsage)
	}
}

// TestTypeBase_MatchesTheOpenCodePlugin keeps the plugin's own copy of the
// base in step: the plugin mints types for the codes it raises itself.
func TestTypeBase_MatchesTheOpenCodePlugin(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "adapters", "opencode", "veil-plugin.js"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `const TYPE_BASE = "` + TypeBase + `";`; !strings.Contains(string(src), want) {
		t.Fatalf("veil-plugin.js does not declare %s", want)
	}
}
