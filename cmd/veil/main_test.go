package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

// Every test below that triggers a rewrite points the pseudonym store at
// a directory this test owns (t.TempDir(), via XDG_STATE_HOME) instead of
// the real default state directory, so the suite never touches (or
// leaves files behind in) the machine running it.

func TestRun_ClaudeCode_DNIInToolArgs_RewritesAndExitsZero(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	stdin := strings.NewReader(`{
		"hook_event_name": "PreToolUse",
		"session_id": "sess-1",
		"tool_name": "Bash",
		"tool_input": {"command": "echo 12345678Z"}
	}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"claude-code"}, stdin, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0 (PreToolUse rewrite is communicated via JSON)", exitCode)
	}
	if !strings.Contains(stdout.String(), `"updatedInput"`) {
		t.Fatalf("stdout = %q, want it to contain updatedInput", stdout.String())
	}
	if strings.Contains(stdout.String(), "12345678Z") {
		t.Fatalf("stdout = %q, still contains the original DNI", stdout.String())
	}
}

func TestRun_ClaudeCode_UserPromptSubmit_DNI_RewritesAndExitsZero(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	stdin := strings.NewReader(`{"hook_event_name": "UserPromptSubmit", "session_id": "sess-1", "user_input": "DNI 12345678Z"}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"claude-code"}, stdin, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0 (a rewrite lets the prompt proceed)", exitCode)
	}
	if strings.Contains(stdout.String(), "12345678Z") {
		t.Fatalf("stdout = %q, still contains the original DNI", stdout.String())
	}
}

func TestRun_OpenCode_DNIInToolArgs_RewritesAndExitsZero(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	stdin := strings.NewReader(`{"event": "tool.execute.before", "sessionID": "ses-1", "tool": "bash", "args": {"command": "echo 12345678Z"}}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"opencode"}, stdin, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0 (a rewrite lets the call proceed)", exitCode)
	}
	if !strings.Contains(stdout.String(), `"action":"rewrite"`) {
		t.Fatalf("stdout = %q, want it to contain a rewrite action", stdout.String())
	}
	if strings.Contains(stdout.String(), "12345678Z") {
		t.Fatalf("stdout = %q, still contains the original DNI", stdout.String())
	}
}

func TestRun_OpenCode_CleanCall_ExitsZero(t *testing.T) {
	stdin := strings.NewReader(`{"event": "tool.execute.before", "tool": "read", "args": {"filePath": "README.md"}}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"opencode"}, stdin, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), `"action":"allow"`) {
		t.Fatalf("stdout = %q, want it to contain an allow action", stdout.String())
	}
}

// parseProblem asserts stderr is exactly one RFC 9457 problem line with a
// type and returns it decoded. It never looks at title or detail text.
func parseProblem(t *testing.T, stderr string) map[string]any {
	t.Helper()
	if strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
		t.Fatalf("stderr = %q, want exactly one line", stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stderr), &got); err != nil {
		t.Fatalf("stderr = %q is not JSON: %v", stderr, err)
	}
	if _, ok := got["type"].(string); !ok {
		t.Fatalf("stderr problem %v has no type", got)
	}
	return got
}

func assertProblem(t *testing.T, stderr string, want problem.Code) {
	t.Helper()
	got := parseProblem(t, stderr)
	if got["type"] != want.Type() || got["code"] != string(want) {
		t.Fatalf("problem = %v, want type %q and code %q", got, want.Type(), want)
	}
}

const (
	dniTool  = `{"event": "tool.execute.before", "sessionID": "sess-1", "tool": "bash", "args": {"command": "echo 12345678Z"}}`
	dniHook  = `{"hook_event_name": "PreToolUse", "session_id": "sess-1", "tool_name": "Bash", "tool_input": {"command": "echo 12345678Z"}}`
	ccFailed = 2 // Claude Code blocks only on exit 2
	ocFailed = problem.ExitFailedClosed
)

// TestRun_Failures_ReportOneProblemAndTheExitClass is one case per code
// the binary can raise today: the problem's type and code, and the exit
// code, which is the usage class or the host's failed-closed code.
func TestRun_Failures_ReportOneProblemAndTheExitClass(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		stdin    string
		setup    func(t *testing.T)
		wantCode problem.Code
		wantExit int
	}{
		{name: "no host argument", args: nil, wantCode: problem.Usage, wantExit: problem.ExitUsage},
		{name: "two arguments", args: []string{"opencode", "extra"}, stdin: dniTool, wantCode: problem.Usage, wantExit: problem.ExitUsage},
		{name: "unknown host", args: []string{"some-other-host"}, stdin: `{}`, wantCode: problem.Usage, wantExit: problem.ExitUsage},
		{name: "claude-code invalid JSON", args: []string{"claude-code"}, stdin: `not json`, wantCode: problem.InputInvalid, wantExit: ccFailed},
		{name: "opencode invalid JSON", args: []string{"opencode"}, stdin: `not json`, wantCode: problem.InputInvalid, wantExit: ocFailed},
		{name: "claude-code unsupported event", args: []string{"claude-code"}, stdin: `{"hook_event_name": "Stop"}`, wantCode: problem.InputInvalid, wantExit: ccFailed},
		{name: "opencode unsupported event", args: []string{"opencode"}, stdin: `{"event": "prompt.submit", "args": {}}`, wantCode: problem.InputInvalid, wantExit: ocFailed},
		{
			name: "claude-code catalog unreadable", args: []string{"claude-code"}, stdin: dniHook,
			setup:    func(t *testing.T) { t.Setenv("VEIL_CATALOG", filepath.Join(t.TempDir(), "missing.json")) },
			wantCode: problem.CatalogUnreadable, wantExit: ccFailed,
		},
		{
			name: "opencode catalog unreadable", args: []string{"opencode"}, stdin: dniTool,
			setup:    func(t *testing.T) { t.Setenv("VEIL_CATALOG", filepath.Join(t.TempDir(), "missing.json")) },
			wantCode: problem.CatalogUnreadable, wantExit: ocFailed,
		},
		{
			name: "claude-code policy unreadable", args: []string{"claude-code"}, stdin: dniHook,
			setup:    func(t *testing.T) { t.Setenv("VEIL_POLICY", filepath.Join(t.TempDir(), "missing.json")) },
			wantCode: problem.PolicyUnreadable, wantExit: ccFailed,
		},
		{
			name: "opencode policy invalid", args: []string{"opencode"}, stdin: dniTool,
			setup:    func(t *testing.T) { t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{}}`)) },
			wantCode: problem.PolicyInvalid, wantExit: ocFailed,
		},
		{
			name: "claude-code policy and catalog ambiguous", args: []string{"claude-code"}, stdin: dniHook,
			setup: func(t *testing.T) {
				t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"dni":{"action":"rewrite"}}}`))
				t.Setenv("VEIL_CATALOG", filepath.Join("testdata", "equivalence", "catalog.json"))
			},
			wantCode: problem.PolicyInvalid, wantExit: ccFailed,
		},
		{
			name: "opencode store corrupt", args: []string{"opencode"}, stdin: dniTool,
			setup:    corruptSession,
			wantCode: problem.StoreCorrupt, wantExit: ocFailed,
		},
		{
			name: "claude-code store corrupt", args: []string{"claude-code"}, stdin: dniHook,
			setup:    corruptSession,
			wantCode: problem.StoreCorrupt, wantExit: ccFailed,
		},
		{
			name: "opencode store unwritable", args: []string{"opencode"}, stdin: dniTool,
			setup:    unwritableStore,
			wantCode: problem.StoreIO, wantExit: ocFailed,
		},
		{
			name: "claude-code store unwritable", args: []string{"claude-code"}, stdin: dniHook,
			setup:    unwritableStore,
			wantCode: problem.StoreIO, wantExit: ccFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			if tc.setup != nil {
				tc.setup(t)
			}
			var stdout, stderr bytes.Buffer

			exitCode := run(tc.args, strings.NewReader(tc.stdin), &stdout, &stderr)

			if exitCode != tc.wantExit {
				t.Fatalf("exitCode = %d, want %d", exitCode, tc.wantExit)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want nothing on a failure", stdout.String())
			}
			assertProblem(t, stderr.String(), tc.wantCode)
		})
	}
}

// corruptSession leaves an unparsable session file where the store will
// look for sess-1.
func corruptSession(t *testing.T) {
	dir := filepath.Join(os.Getenv("XDG_STATE_HOME"), "veil", "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sess-1.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// unwritableStore puts a regular file where the store directory must go.
func unwritableStore(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(state, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", state)
}

// TestFail_EveryCode_WritesItsTypeAndExitsWithTheHostFailureCode covers
// the codes later changes raise (store keys, keyring, lock, evidence) and
// the catch-all: whatever the code, the problem carries its type and the
// exit code is the host's failed-closed code.
func TestFail_EveryCode_WritesItsTypeAndExitsWithTheHostFailureCode(t *testing.T) {
	for _, h := range []struct {
		name string
		exit int
	}{{"claude-code", ccFailed}, {"opencode", ocFailed}} {
		host := hostsByName[h.name]
		for _, code := range problem.All() {
			t.Run(h.name+"/"+string(code), func(t *testing.T) {
				var stderr bytes.Buffer
				if got := host.fail(&stderr, code); got != h.exit {
					t.Fatalf("exit = %d, want %d", got, h.exit)
				}
				assertProblem(t, stderr.String(), code)
			})
		}
	}
}

func TestClassifyEvaluateError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want problem.Code
	}{
		{"unsupported capability", fmt.Errorf("wrap: %w", &domain.UnsupportedCapabilityError{Host: domain.HostClaudeCode, Capability: domain.CapabilityToolOutputRedact}), problem.CapabilityUnsupported},
		{"corrupt session file", fmt.Errorf("pseudonymstore: parse: %w", json.Unmarshal([]byte("{"), &map[string]any{})), problem.StoreCorrupt},
		{"store path error", fmt.Errorf("pseudonymstore: create: %w", &fs.PathError{Op: "mkdir", Path: "/x", Err: fs.ErrPermission}), problem.StoreIO},
		{"lock timeout", fmt.Errorf("wrap: %w", pseudonymstore.ErrLocked), problem.StoreLocked},
		{"key missing", fmt.Errorf("wrap: %w", pseudonymstore.ErrKeyMissing), problem.StoreKeyMissing},
		{"key invalid", fmt.Errorf("wrap: %w", pseudonymstore.ErrKeyInvalid), problem.StoreKeyInvalid},
		{"keyring unavailable", fmt.Errorf("wrap: %w", pseudonymstore.ErrKeyringUnavailable), problem.StoreKeyringUnavailable},
		{"corrupt store", fmt.Errorf("wrap: %w", pseudonymstore.ErrCorrupt), problem.StoreCorrupt},
		{"anything else", errors.New("boom"), problem.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyEvaluateError(tc.err); got != tc.want {
				t.Fatalf("classifyEvaluateError = %s, want %s", got, tc.want)
			}
		})
	}
}

// seededValues are detected values the failure inputs below carry. No
// problem may echo any of them (shared corpus idea with #6).
var seededValues = []string{"12345678Z", "ES9121000418450200051332", "ana.garcia@example.com", "+34612345678", "612345678"}

func TestRun_FailureProblems_NeverCarryDetectedValues(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		stdin string
		setup func(t *testing.T)
	}{
		{"invalid JSON", []string{"claude-code"}, `12345678Z ana.garcia@example.com`, nil},
		{"trailing data", []string{"opencode"}, dniTool + ` ES9121000418450200051332`, nil},
		{"unsupported claude-code event", []string{"claude-code"}, `{"hook_event_name": "ana.garcia@example.com 12345678Z"}`, nil},
		{"unsupported opencode event", []string{"opencode"}, `{"event": "ES9121000418450200051332 +34612345678"}`, nil},
		{"unknown host", []string{"12345678Z"}, dniTool, nil},
		{"wrong JSON type", []string{"opencode"}, `{"event": "tool.execute.before", "args": "12345678Z ana.garcia@example.com"}`, nil},
		{"corrupt store", []string{"opencode"}, dniTool, corruptSession},
		{"unwritable store", []string{"opencode"}, `{"event": "tool.execute.before", "sessionID": "ana.garcia@example.com", "tool": "bash", "args": {"command": "echo 12345678Z"}}`, unwritableStore},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			if tc.setup != nil {
				tc.setup(t)
			}
			var stdout, stderr bytes.Buffer

			run(tc.args, strings.NewReader(tc.stdin), &stdout, &stderr)

			parseProblem(t, stderr.String())
			for _, v := range seededValues {
				if strings.Contains(stderr.String(), v) {
					t.Fatalf("problem %q carries the detected value %q", stderr.String(), v)
				}
			}
		})
	}
}

func TestRun_OpenCode_Deny_IsADecision(t *testing.T) {
	stdin := strings.NewReader(`{"event": "tool.execute.before", "tool": "read", "args": {"filePath": "/home/user/project/.env"}}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"opencode"}, stdin, &stdout, &stderr)

	if exitCode != problem.ExitDecision {
		t.Fatalf("exitCode = %d, want %d", exitCode, problem.ExitDecision)
	}
	if !strings.Contains(stdout.String(), `"action":"deny"`) {
		t.Fatalf("stdout = %q, want a deny action", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing for a decision", stderr.String())
	}
}
