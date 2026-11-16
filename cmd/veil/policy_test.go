package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
)

var updateGolden = flag.Bool("update", false, "rewrite cmd/veil/testdata/equivalence/golden.json from the current behaviour")

type equivalenceEvent struct {
	Name    string          `json:"name"`
	Host    string          `json:"host"`
	Payload json.RawMessage `json:"payload"`
}

type runResult struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func loadEquivalenceEvents(t *testing.T) []equivalenceEvent {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "equivalence", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []equivalenceEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e equivalenceEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("events.jsonl: %v", err)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

// runEvent runs one event through the CLI with a fresh pseudonym store,
// so token numbering never depends on what ran before it. Its stdout is
// recorded without the additive evidence member (see withoutEvidence).
func runEvent(t *testing.T, e equivalenceEvent, policyPath string) runResult {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_EVIDENCE_FILE", "")
	t.Setenv("VEIL_CATALOG_REVISION", "")
	t.Setenv("VEIL_CATALOG", filepath.Join("testdata", "equivalence", "catalog.json"))
	t.Setenv("VEIL_POLICY", policyPath)
	if policyPath == "" {
		os.Unsetenv("VEIL_POLICY")
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{e.Host}, bytes.NewReader(e.Payload), &stdout, &stderr)
	return runResult{ExitCode: code, Stdout: withoutEvidence(stdout.String()), Stderr: stderr.String()}
}

// withoutEvidence cuts the opencode answer's evidence member, which is
// always the last member and differs per run (id, time). Inside a JSON
// string a quote is escaped, so the first `,"evidence":{` is the
// top-level member. Everything before it must stay byte-identical.
func withoutEvidence(stdout string) string {
	if i := strings.Index(stdout, `,"evidence":{`); i >= 0 {
		return stdout[:i] + "}"
	}
	return stdout
}

// TestRun_DefaultPolicy_Equivalence proves the embedded default policy is
// today's behaviour: every event gives byte-identical output with no
// VEIL_POLICY, with VEIL_POLICY pointing at the published default file,
// and as recorded in golden.json before the policy file existed.
func TestRun_DefaultPolicy_Equivalence(t *testing.T) {
	events := loadEquivalenceEvents(t)
	goldenPath := filepath.Join("testdata", "equivalence", "golden.json")
	defaultFile := filepath.Join("..", "..", "internal", "policy", "default.json")

	got := make(map[string]runResult, len(events))
	for _, e := range events {
		got[e.Name] = runEvent(t, e, "")
	}

	if *updateGolden {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]runResult
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) != len(events) {
		t.Fatalf("golden has %d events, events.jsonl has %d", len(golden), len(events))
	}

	for _, e := range events {
		withFile := runEvent(t, e, defaultFile)
		if got[e.Name] != golden[e.Name] {
			t.Errorf("%s: no VEIL_POLICY = %+v, golden = %+v", e.Name, got[e.Name], golden[e.Name])
		}
		if withFile != golden[e.Name] {
			t.Errorf("%s: VEIL_POLICY=default.json = %+v, golden = %+v", e.Name, withFile, golden[e.Name])
		}
	}
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRun_VEIL_POLICY_IsHonoured guards the equivalence test against
// passing vacuously: a policy that denies DNI must change the outcome of
// a DNI prompt from a rewrite (exit 0) to a block (exit 2).
func TestRun_VEIL_POLICY_IsHonoured(t *testing.T) {
	path := writePolicy(t, `{"version":"1.0","detectors":{"dni":{"action":"deny"}}}`)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_CATALOG", "")
	t.Setenv("VEIL_POLICY", path)
	var stdout, stderr bytes.Buffer

	code := run([]string{"claude-code"}, bytes.NewReader([]byte(`{"hook_event_name":"UserPromptSubmit","session_id":"s","user_input":"DNI 12345678Z"}`)), &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit = %d, want 2 (DNI denied by policy)", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on a deny", stdout.String())
	}
}

// TestRun_VEIL_POLICY_Disabled_DetectorDoesNotRun shows that a detector
// missing from the policy does not run.
func TestRun_VEIL_POLICY_Disabled_DetectorDoesNotRun(t *testing.T) {
	path := writePolicy(t, `{"version":"1.0","detectors":{"email":{"action":"rewrite"}}}`)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_CATALOG", "")
	t.Setenv("VEIL_POLICY", path)
	var stdout, stderr bytes.Buffer

	code := run([]string{"claude-code"}, bytes.NewReader([]byte(`{"hook_event_name":"UserPromptSubmit","session_id":"s","user_input":"DNI 12345678Z"}`)), &stdout, &stderr)

	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("exit = %d stdout = %q, want a plain allow (dni not enabled)", code, stdout.String())
	}
}

func TestRun_PolicyCommand(t *testing.T) {
	valid := writePolicy(t, `{"version":"1.0","detectors":{"email":{"action":"rewrite"}}}`)
	broken := writePolicy(t, `{"version":"1.0","detectors":{"email":{"action":"allow"}}}`)
	defaultFile := filepath.Join("..", "..", "internal", "policy", "default.json")

	cases := map[string]struct {
		args   []string
		env    string
		exit   int
		digest string
	}{
		"default":            {nil, "", 0, policy.Default().Digest()},
		"default file":       {[]string{defaultFile}, "", 0, policy.Default().Digest()},
		"from VEIL_POLICY":   {nil, defaultFile, 0, policy.Default().Digest()},
		"explicit file":      {[]string{valid}, "", 0, ""},
		"invalid file":       {[]string{broken}, "", problem.ExitFailedClosed, ""},
		"too many arguments": {[]string{valid, valid}, "", problem.ExitUsage, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("VEIL_POLICY", tc.env)
			var stdout, stderr bytes.Buffer

			code := run(append([]string{"policy"}, tc.args...), bytes.NewReader(nil), &stdout, &stderr)

			if code != tc.exit {
				t.Fatalf("exit = %d, want %d", code, tc.exit)
			}
			if tc.exit != 0 {
				if stdout.Len() != 0 {
					t.Fatalf("stdout = %q, want empty on failure", stdout.String())
				}
				want := problem.PolicyInvalid
				if tc.exit == problem.ExitUsage {
					want = problem.Usage
				}
				assertProblem(t, stderr.String(), want)
				return
			}
			var out struct{ Version, Digest string }
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("stdout %q is not JSON: %v", stdout.String(), err)
			}
			if out.Version != "1.0" || len(out.Digest) != len("sha256:")+64 {
				t.Fatalf("out = %+v", out)
			}
			if tc.digest != "" && out.Digest != tc.digest {
				t.Fatalf("digest = %s, want %s", out.Digest, tc.digest)
			}
		})
	}
}
