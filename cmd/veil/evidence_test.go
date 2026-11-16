package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/evidence"
	"github.com/FullFran/veil/internal/hosts/claudecode"
	"github.com/FullFran/veil/internal/hosts/opencode"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
)

// evidenceEnv isolates one run: its own pseudonym store, no ambient
// policy or catalog, and the evidence file in a directory the test owns.
func evidenceEnv(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_POLICY", "")
	t.Setenv("VEIL_CATALOG", "")
	t.Setenv("VEIL_CATALOG_REVISION", "")
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	t.Setenv("VEIL_EVIDENCE_FILE", path)
	return path
}

func readRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()
	var records []map[string]any
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			t.Fatalf("evidence line %q is not JSON: %v", scanner.Text(), err)
		}
		records = append(records, m)
	}
	return records
}

func member(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var v any = m
	for _, key := range path {
		obj, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%v: %q is not inside an object", path, key)
		}
		v = obj[key]
	}
	return v
}

var decisionEvents = []struct {
	name     string
	host     string
	payload  string
	actionID float64
}{
	{"cc-allow", "claude-code", `{"hook_event_name":"UserPromptSubmit","session_id":"s1","user_input":"hola"}`, 1},
	{"cc-rewrite", "claude-code", `{"hook_event_name":"UserPromptSubmit","session_id":"s1","user_input":"DNI 12345678Z"}`, 4},
	{"cc-deny", "claude-code", `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Read","tool_input":{"file_path":"/repo/.env"}}`, 2},
	{"oc-allow", "opencode", `{"event":"tool.execute.before","sessionID":"s1","tool":"bash","args":{"command":"ls"}}`, 1},
	{"oc-rewrite", "opencode", `{"event":"tool.execute.before","sessionID":"s1","tool":"bash","args":{"command":"echo 12345678Z"}}`, 4},
	{"oc-deny", "opencode", `{"event":"tool.execute.before","sessionID":"s1","tool":"read","args":{"filePath":"/repo/.env"}}`, 2},
}

// TestRun_Evidence_OneRecordPerDecision: allow, deny and rewrite each
// append exactly one record, on both hosts, carrying the decision and the
// active policy's digest.
func TestRun_Evidence_OneRecordPerDecision(t *testing.T) {
	for _, e := range decisionEvents {
		t.Run(e.name, func(t *testing.T) {
			path := evidenceEnv(t)
			var stdout, stderr bytes.Buffer
			code := run([]string{e.host}, strings.NewReader(e.payload), &stdout, &stderr)
			if strings.Contains(stderr.String(), `"code"`) {
				t.Fatalf("exit %d with a problem: %s", code, stderr.String())
			}

			records := readRecords(t, path)
			if len(records) != 1 {
				t.Fatalf("evidence file has %d records, want 1", len(records))
			}
			rec := records[0]
			if rec["specversion"] != "1.0" || rec["type"] != evidence.Type {
				t.Errorf("envelope = %v/%v, want a veil CloudEvent", rec["specversion"], rec["type"])
			}
			if got := member(t, rec, "data", "action_id"); got != e.actionID {
				t.Errorf("action_id = %v, want %v", got, e.actionID)
			}
			if got := member(t, rec, "data", "data_security", "policy", "uid"); got != policy.Default().Digest() {
				t.Errorf("policy uid = %v, want the default policy digest", got)
			}
			if got := member(t, rec, "data", "actor", "app_name"); got != e.host {
				t.Errorf("actor.app_name = %v, want %s", got, e.host)
			}
			if got := member(t, rec, "data", "actor", "session", "uid"); got != "s1" {
				t.Errorf("session uid = %v, want s1", got)
			}
		})
	}
}

// TestRun_Evidence_NoFileConfigured_WritesNothing: without
// VEIL_EVIDENCE_FILE veil writes no file and its claude-code output is
// unchanged.
func TestRun_Evidence_NoFileConfigured_WritesNothing(t *testing.T) {
	path := evidenceEnv(t)
	t.Setenv("VEIL_EVIDENCE_FILE", "")
	var stdout, stderr bytes.Buffer
	run([]string{"claude-code"}, strings.NewReader(decisionEvents[1].payload), &stdout, &stderr)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("evidence file exists without VEIL_EVIDENCE_FILE: %v", err)
	}
}

// TestRun_Evidence_WriteFailure_FailsClosed: a record that cannot be
// written blocks the event (HCS-0005-R012) with VEIL_EVIDENCE_WRITE and
// nothing on stdout, on every decision kind and both hosts.
func TestRun_Evidence_WriteFailure_FailsClosed(t *testing.T) {
	wantExit := map[string]int{"claude-code": claudecode.FailureExitCode, "opencode": opencode.FailureExitCode}
	for _, e := range decisionEvents {
		t.Run(e.name, func(t *testing.T) {
			evidenceEnv(t)
			t.Setenv("VEIL_EVIDENCE_FILE", t.TempDir()) // a directory: unwritable as a file
			var stdout, stderr bytes.Buffer
			code := run([]string{e.host}, strings.NewReader(e.payload), &stdout, &stderr)
			if code != wantExit[e.host] {
				t.Errorf("exit = %d, want %d", code, wantExit[e.host])
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			assertProblem(t, stderr.String(), problem.EvidenceWrite)
		})
	}
}

// TestRun_OpenCode_EvidenceMember: opencode answers carry the same record
// as an additive evidence member; claude-code stdout carries none.
func TestRun_OpenCode_EvidenceMember(t *testing.T) {
	for _, e := range decisionEvents {
		t.Run(e.name, func(t *testing.T) {
			path := evidenceEnv(t)
			var stdout, stderr bytes.Buffer
			run([]string{e.host}, strings.NewReader(e.payload), &stdout, &stderr)
			if e.host == "claude-code" {
				if strings.Contains(stdout.String(), "evidence") {
					t.Fatalf("claude-code stdout = %q, want no evidence member", stdout.String())
				}
				return
			}
			var out map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("stdout %q: %v", stdout.String(), err)
			}
			ev, ok := out["evidence"].(map[string]any)
			if !ok {
				t.Fatalf("stdout = %s, want an evidence object", stdout.String())
			}
			if ev["id"] != readRecords(t, path)[0]["id"] {
				t.Errorf("evidence id %v differs from the file record", ev["id"])
			}
			if member(t, ev, "data", "action_id") != e.actionID {
				t.Errorf("evidence action_id = %v, want %v", member(t, ev, "data", "action_id"), e.actionID)
			}
		})
	}
}

func TestRun_CatalogRevision(t *testing.T) {
	t.Run("valid revision is recorded as-is", func(t *testing.T) {
		path := evidenceEnv(t)
		t.Setenv("VEIL_CATALOG_REVISION", "clients:r42")
		var stdout, stderr bytes.Buffer
		run([]string{"claude-code"}, strings.NewReader(decisionEvents[0].payload), &stdout, &stderr)
		if got := member(t, readRecords(t, path)[0], "data", "unmapped", "veil", "catalog_revision"); got != "clients:r42" {
			t.Fatalf("catalog_revision = %v, want clients:r42", got)
		}
	})
	t.Run("invalid revision fails closed", func(t *testing.T) {
		for _, host := range []string{"claude-code", "opencode"} {
			path := evidenceEnv(t)
			t.Setenv("VEIL_CATALOG_REVISION", "María Pérez")
			var stdout, stderr bytes.Buffer
			code := run([]string{host}, strings.NewReader(decisionEvents[0].payload), &stdout, &stderr)
			if code == problem.ExitDecision || stdout.Len() != 0 {
				t.Errorf("%s: exit %d stdout %q, want a failure", host, code, stdout.String())
			}
			assertProblem(t, stderr.String(), problem.CatalogRevisionInvalid)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("%s: evidence written despite a startup failure", host)
			}
		}
	})
}

// TestRun_Evidence_PolicyFingerprint: the recorded fingerprint changes
// with the detector set or an action, and not with formatting or the
// catalog's names (those are traced only by VEIL_CATALOG_REVISION).
func TestRun_Evidence_PolicyFingerprint(t *testing.T) {
	fingerprint := func(t *testing.T, policyDoc, catalog string) any {
		t.Helper()
		path := evidenceEnv(t)
		t.Setenv("VEIL_POLICY", writePolicy(t, policyDoc))
		if catalog != "" {
			catalogPath := filepath.Join(t.TempDir(), "catalog.json")
			if err := os.WriteFile(catalogPath, []byte(catalog), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("VEIL_CATALOG", catalogPath)
		}
		var stdout, stderr bytes.Buffer
		run([]string{"claude-code"}, strings.NewReader(decisionEvents[0].payload), &stdout, &stderr)
		return member(t, readRecords(t, path)[0], "data", "data_security", "policy", "uid")
	}
	base := fingerprint(t, `{"version":"1.0","detectors":{"dni":{"action":"rewrite"},"name-catalog":{"action":"rewrite"}}}`, `["Ana Ruiz"]`)
	reformatted := fingerprint(t, `{ "detectors": {"name-catalog":{"action":"rewrite"}, "dni": {"action": "rewrite"}}, "version": "1.0" }`, `["Ana Ruiz"]`)
	otherNames := fingerprint(t, `{"version":"1.0","detectors":{"dni":{"action":"rewrite"},"name-catalog":{"action":"rewrite"}}}`, `["Luis Gil"]`)
	otherAction := fingerprint(t, `{"version":"1.0","detectors":{"dni":{"action":"deny"},"name-catalog":{"action":"rewrite"}}}`, `["Ana Ruiz"]`)
	otherSet := fingerprint(t, `{"version":"1.0","detectors":{"dni":{"action":"rewrite"},"email":{"action":"rewrite"},"name-catalog":{"action":"rewrite"}}}`, `["Ana Ruiz"]`)

	if base != reformatted || base != otherNames {
		t.Errorf("fingerprint changed with formatting or catalog names: %v %v %v", base, reformatted, otherNames)
	}
	if base == otherAction || base == otherSet {
		t.Errorf("fingerprint did not change with the detector set or an action: %v %v %v", base, otherAction, otherSet)
	}
}

var markerPattern = regexp.MustCompile(`\[[A-Z]+-[0-9]{3}\]`)

// inputStrings collects every string in an event payload except the
// members that are metadata, not content: event names, session id and
// tool name, which a record carries on purpose.
func inputStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			inputStrings(e, out)
		}
	case map[string]any:
		for k, e := range x {
			switch k {
			case "hook_event_name", "session_id", "tool_name", "event", "sessionID", "tool":
				continue
			}
			*out = append(*out, k)
			inputStrings(e, out)
		}
	}
}

// TestRun_Evidence_NeverCarriesInput runs every equivalence event (both
// hosts, every event kind, seeded DNI, NIE, IBAN, phone, email and
// catalog names) and checks that neither the evidence file nor the
// opencode evidence member carries any input string, in clear, compacted
// or lowercased, nor any pseudonym marker.
func TestRun_Evidence_NeverCarriesInput(t *testing.T) {
	compact := strings.NewReplacer(" ", "", ".", "", "-", "")
	checked := 0
	for _, e := range loadEquivalenceEvents(t) {
		path := evidenceEnv(t)
		t.Setenv("VEIL_CATALOG", filepath.Join("testdata", "equivalence", "catalog.json"))
		var stdout, stderr bytes.Buffer
		run([]string{e.Host}, bytes.NewReader(e.Payload), &stdout, &stderr)

		var sinks []string
		if raw, err := os.ReadFile(path); err == nil {
			sinks = append(sinks, string(raw))
		}
		if e.Host == "opencode" {
			var out map[string]json.RawMessage
			if json.Unmarshal(stdout.Bytes(), &out) == nil && out["evidence"] != nil {
				sinks = append(sinks, string(out["evidence"]))
			}
		}
		if len(sinks) == 0 {
			continue // a failure (problem details) makes no decision and no record
		}

		var payload any
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		var inputs []string
		inputStrings(payload, &inputs)
		for _, sink := range sinks {
			if m := markerPattern.FindString(sink); m != "" {
				t.Errorf("%s: evidence carries marker %q", e.Name, m)
			}
			for _, in := range inputs {
				for _, form := range []string{in, strings.ToLower(in), compact.Replace(in), strings.ToLower(compact.Replace(in))} {
					if len([]rune(form)) >= 4 && strings.Contains(sink, form) {
						t.Errorf("%s: evidence carries input %q", e.Name, form)
					}
				}
			}
			checked++
		}
	}
	if checked < 10 {
		t.Fatalf("checked only %d evidence sinks; the test would pass vacuously", checked)
	}
}
