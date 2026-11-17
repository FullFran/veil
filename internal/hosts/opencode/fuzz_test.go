package opencode_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/opencode"
)

// FuzzPipeline (go test -fuzz) feeds arbitrary bytes through what a hook
// invocation does with the OpenCode shim's JSON: Decode, the policy with every
// detector veil ships, and Encode. Decode either fails or yields an
// OpenCode event; Encode answers every decision of a decoded event with JSON
// and a known exit code; and a rewrite never sends back, in any JSON
// string or key, a value a detector found, except to a tool that writes
// to disk, which gets the real values back by design.
func FuzzPipeline(f *testing.F) {
	for _, seed := range []string{
		`{"event":"chat.message","sessionID":"s","fields":{"p1":"mi DNI es 12345678Z"}}`,
		`{"event":"tool.execute.before","sessionID":"s","tool":"bash","args":{"command":"echo 612 345 678","n":612345678}}`,
		`{"event":"tool.execute.before","sessionID":"s","tool":"write","args":{"filePath":"a.txt","content":"[TEL-001] juan@example.com"}}`,
		`{"event":"tool.execute.after","sessionID":"s","tool":"read","fields":{"output":"ES91 2100 0418 4502 0005 1332"}}`,
		`{"event":"some.other.event"}`,
		`not json`,
		`{}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		event, err := opencode.Decode(raw)
		if err != nil {
			return
		}
		if event.Host != domain.HostOpenCode {
			t.Fatalf("Decode(%q) host = %q", raw, event.Host)
		}
		registry := fuzzRegistry()
		decision, err := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore()).Evaluate(event)
		if err != nil {
			return // fails closed before anything is encoded
		}
		result, err := opencode.Encode(event, decision)
		if err != nil {
			t.Fatalf("Encode(%q) of a %v decision: %v", raw, decision.Kind, err)
		}
		if result.ExitCode != 0 && result.ExitCode != opencode.FailureExitCode {
			t.Fatalf("Encode(%q) exit code = %d", raw, result.ExitCode)
		}
		if len(result.Stdout) == 0 {
			return
		}
		// UseNumber: a number outside float64 (1E700) is valid JSON
		// (RFC 8259) and is passed through as the host sent it.
		dec := json.NewDecoder(bytes.NewReader(result.Stdout))
		dec.UseNumber()
		var out any
		if err := dec.Decode(&out); err != nil {
			t.Fatalf("Encode(%q) stdout is not JSON: %v", raw, err)
		}
		if decision.Kind != domain.Rewrite || writeTools[strings.ToLower(event.ToolName)] {
			return // a write tool gets the real values back on purpose (rehydration)
		}
		findings, err := registry.DetectAll(event)
		if err != nil {
			t.Fatalf("DetectAll: %v", err)
		}
		for _, finding := range findings {
			if leaked := findString(out, finding.Match); finding.Match != "" && leaked != "" {
				t.Fatalf("rewrite of %q sends back the found value %q in %q", raw, finding.Match, leaked)
			}
		}
	})
}

// fuzzRegistry is every detector veil ships except the name catalog,
// which needs a catalog file.
func fuzzRegistry() *domain.Registry {
	return domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewIBANDetector(),
		domain.NewEmailDetector(),
		domain.NewPhoneDetector(),
		domain.NewSecretPathDetector(),
		domain.NewBinaryContentDetector(),
	)
}

// writeTools are the tools whose markers veil rehydrates (Policy.Evaluate).
var writeTools = map[string]bool{"write": true, "edit": true, "multiedit": true, "patch": true}

// findString returns the first string or object key in v that contains s.
func findString(v any, s string) string {
	switch v := v.(type) {
	case string:
		if strings.Contains(v, s) {
			return v
		}
	case []any:
		for _, item := range v {
			if found := findString(item, s); found != "" {
				return found
			}
		}
	case map[string]any:
		for key, item := range v {
			if strings.Contains(key, s) {
				return key
			}
			if found := findString(item, s); found != "" {
				return found
			}
		}
	}
	return ""
}
