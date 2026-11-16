package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Issue #24: values written with full-width forms or with zero-width
// characters inside them must be pseudonymized on every host mode, the
// same as their plain form. Values are synthetic.
var lookalikeInputs = []struct {
	name    string
	text    string
	written []string // the values as written; none may reach stdout
	tokens  []string // the pseudonym tokens that must replace them
}{
	{
		name:    "full-width forms",
		text:    "dni １２３４５６７８Ｚ mail zed＠example.org tel ６１２３４５６７８",
		written: []string{"１２３４５６７８Ｚ", "zed＠example.org", "６１２３４５６７８"},
		tokens:  []string{"[DNI-001]", "[EMAIL-001]", "[TEL-001]"},
	},
	{
		name:    "zero-width space inside the value",
		text:    "dni 1234\u200b5678Z, zed@exa\u200bmple.org",
		written: []string{"1234\u200b5678Z", "zed@exa\u200bmple.org"},
		tokens:  []string{"[DNI-001]", "[EMAIL-001]"},
	},
}

func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertLookalikesRewritten decodes stdout as JSON (so escaped and raw
// characters compare the same) and checks no written value is left and
// every token is present.
func assertLookalikesRewritten(t *testing.T, exitCode int, stdout string, written, tokens []string) {
	t.Helper()
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0 (a rewrite lets the event proceed)", exitCode)
	}
	var decoded any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout %q is not JSON: %v", stdout, err)
	}
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(decoded); err != nil {
		t.Fatal(err)
	}
	for _, w := range written {
		if strings.Contains(out.String(), w) {
			t.Errorf("output still contains the written value %q: %s", w, out.String())
		}
	}
	for _, token := range tokens {
		if !strings.Contains(out.String(), token) {
			t.Errorf("output lacks token %s: %s", token, out.String())
		}
	}
}

func TestRun_ClaudeCode_Lookalikes_Rewritten(t *testing.T) {
	for _, tc := range lookalikeInputs {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			stdin := strings.NewReader(`{"hook_event_name": "UserPromptSubmit", "session_id": "sess-1", "user_input": ` + jsonString(t, tc.text) + `}`)
			var stdout, stderr bytes.Buffer
			exitCode := run([]string{"claude-code"}, stdin, &stdout, &stderr)
			assertLookalikesRewritten(t, exitCode, stdout.String(), tc.written, tc.tokens)
		})
	}
}

func TestRun_OpenCode_Lookalikes_Rewritten(t *testing.T) {
	for _, tc := range lookalikeInputs {
		t.Run(tc.name+"/chat.message", func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			stdin := strings.NewReader(`{"event": "chat.message", "sessionID": "ses-1", "fields": {"0": ` + jsonString(t, tc.text) + `}}`)
			var stdout, stderr bytes.Buffer
			exitCode := run([]string{"opencode"}, stdin, &stdout, &stderr)
			assertLookalikesRewritten(t, exitCode, stdout.String(), tc.written, tc.tokens)
		})
		t.Run(tc.name+"/tool.execute.before", func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			stdin := strings.NewReader(`{"event": "tool.execute.before", "sessionID": "ses-1", "tool": "bash", "args": {"command": ` + jsonString(t, "echo "+tc.text) + `}}`)
			var stdout, stderr bytes.Buffer
			exitCode := run([]string{"opencode"}, stdin, &stdout, &stderr)
			assertLookalikesRewritten(t, exitCode, stdout.String(), tc.written, tc.tokens)
		})
	}
}
