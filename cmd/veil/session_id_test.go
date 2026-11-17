package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/problem"
)

// TestRun_MissingSessionID_FailsClosedOnEveryHost proves an event that
// needs a pseudonym and carries no session id (the member absent or
// empty) fails closed with VEIL_SESSION_ID_MISSING on Claude Code and
// OpenCode, and writes nothing to the store: there is no shared
// unknown-session bucket any more.
func TestRun_MissingSessionID_FailsClosedOnEveryHost(t *testing.T) {
	cases := []struct {
		name, host, event string
		exit              int
	}{
		{"claude-code PreToolUse without session_id", "claude-code", `{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo 12345678Z"}}`, ccFailed},
		{"claude-code UserPromptSubmit with an empty session_id", "claude-code", `{"hook_event_name": "UserPromptSubmit", "session_id": "", "user_input": "my DNI is 12345678Z"}`, ccFailed},
		{"opencode tool.execute.before without sessionID", "opencode", `{"event": "tool.execute.before", "tool": "bash", "args": {"command": "echo 12345678Z"}}`, ocFailed},
		{"opencode chat.message with an empty sessionID", "opencode", `{"event": "chat.message", "sessionID": "", "fields": {"0": "my DNI is 12345678Z"}}`, ocFailed},
		{"opencode history without sessionID", "opencode", `{"event": "experimental.chat.messages.transform", "fields": {"0:0:text": "my DNI is 12345678Z"}}`, ocFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			var stdout, stderr bytes.Buffer

			exit := run([]string{tc.host}, strings.NewReader(tc.event), &stdout, &stderr)

			if exit != tc.exit || stdout.Len() != 0 {
				t.Fatalf("exit = %d, stdout %q; want %d and nothing", exit, stdout.String(), tc.exit)
			}
			assertProblem(t, stderr.String(), problem.SessionIDMissing)
			if entries, _ := os.ReadDir(filepath.Dir(sessionFile("x", ""))); len(entries) != 0 {
				t.Fatalf("the store holds %d files for an event with no session", len(entries))
			}
		})
	}
}

// TestRun_MissingSessionID_EventWithoutPseudonym_IsDecided proves the
// refusal is the store's, not the decoder's: an event that needs no
// pseudonym links nothing, so it is still decided.
func TestRun_MissingSessionID_EventWithoutPseudonym_IsDecided(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	exit := run([]string{"opencode"}, strings.NewReader(`{"event": "tool.execute.before", "tool": "bash", "args": {"command": "ls"}}`), io.Discard, io.Discard)
	if exit != problem.ExitDecision {
		t.Fatalf("exit = %d, want %d", exit, problem.ExitDecision)
	}
}

// TestRun_ACS_MissingSessionID_IsRefused proves an ACS request cannot omit
// the session id: the vendored envelope schema requires
// metadata.session_id as a uuid, so an absent or empty one is refused
// before any evaluation.
func TestRun_ACS_MissingSessionID_IsRefused(t *testing.T) {
	isolateACS(t)
	for name, mutate := range map[string]func(meta map[string]any){
		"absent": func(meta map[string]any) { delete(meta, "session_id") },
		"empty":  func(meta map[string]any) { meta["session_id"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var req map[string]any
			if err := json.Unmarshal([]byte(acsRequest(t, "0.1.0", acsRequestID, "write", map[string]string{"content": "12345678Z"})), &req); err != nil {
				t.Fatal(err)
			}
			mutate(req["params"].(map[string]any)["metadata"].(map[string]any))
			raw, _ := json.Marshal(req)

			exit, a, stderr := runACSWith(t, string(raw))

			// The request_id is intact, so the refusal is a final deny.
			if exit != problem.ExitFailedClosed || a.Result == nil || a.Result.Decision != "deny" ||
				len(a.Result.ReasonCodes) != 1 || a.Result.ReasonCodes[0] != string(problem.ACSRequestInvalid) {
				t.Fatalf("exit %d, answer = %+v, want a deny with %s", exit, a, problem.ACSRequestInvalid)
			}
			assertProblem(t, stderr, problem.ACSRequestInvalid)
		})
	}
}

// TestRun_StoreForgetLegacyStem_ErasesAStemNoSessionReaches proves a store
// a veil before #26 left under a name several session ids shared is
// found by that name and erased with forget --legacy-stem, keeping its
// counters, while forgetting one of those ids leaves it alone.
func TestRun_StoreForgetLegacyStem_ErasesAStemNoSessionReaches(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	seed(t, "a_b", "DNI", "12345678Z")
	for _, suffix := range []string{".age", ".ctr"} { // as a veil before #26 named them
		if err := os.Rename(sessionFile("a_b", suffix), filepath.Join(sessionsDir(), "a_b"+suffix)); err != nil {
			t.Fatal(err)
		}
	}

	if exit, _, stderr := storeCmd("forget", "a/b"); exit != problem.ExitDecision {
		t.Fatalf("forget a/b = (%d, %q)", exit, stderr)
	}
	exit, stdout, _ := storeCmd("find", "--value", "12345678Z")
	if got := found(t, stdout); exit != problem.ExitDecision || len(got) != 1 || got[0].LegacyStem != "a_b" || got[0].Session != "" {
		t.Fatalf("find = (%d, %+v), want only legacy_stem a_b", exit, got)
	}

	if exit, _, stderr := storeCmd("forget", "--legacy-stem", "a_b"); exit != problem.ExitDecision {
		t.Fatalf("forget --legacy-stem = (%d, %q)", exit, stderr)
	}
	if _, err := os.Stat(filepath.Join(sessionsDir(), "a_b.age")); !os.IsNotExist(err) {
		t.Fatal("the legacy store survived forget --legacy-stem")
	}
	if _, err := os.Stat(filepath.Join(sessionsDir(), "a_b.ctr")); err != nil {
		t.Fatal("forget --legacy-stem removed the counters")
	}
	if _, stdout, _ := storeCmd("find", "--value", "12345678Z"); len(found(t, stdout)) != 0 {
		t.Fatalf("find after forget = %s", stdout)
	}
}

// TestRun_Store_SessionIDArguments covers the store commands' session
// arguments: an empty id or stem is bad usage, and a stem that is not a
// plain file name is refused as bad usage too.
func TestRun_Store_SessionIDArguments(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	for _, args := range [][]string{
		{"forget", "--legacy-stem"},
		{"forget", "--legacy-stem", ""},
		{"forget", "--legacy-stem", "../x"},
		{"forget", "--legacy-stem", ".."},
	} {
		exit, _, stderr := storeCmd(args...)
		if exit != problem.ExitUsage {
			t.Errorf("%q: exit = %d, want %d", args, exit, problem.ExitUsage)
		}
		assertProblem(t, stderr, problem.Usage)
	}
}
