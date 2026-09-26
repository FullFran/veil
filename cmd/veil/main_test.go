package main

import (
	"bytes"
	"strings"
	"testing"
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

func TestRun_UnknownHost_ExitsOne(t *testing.T) {
	stdin := strings.NewReader(`{}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"some-other-host"}, stdin, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr must explain the unknown host")
	}
}

func TestRun_MissingHostArgument_ExitsOne(t *testing.T) {
	stdin := strings.NewReader(``)
	var stdout, stderr bytes.Buffer

	exitCode := run(nil, stdin, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
}

func TestRun_InvalidJSON_ExitsOne(t *testing.T) {
	stdin := strings.NewReader(`not json`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"claude-code"}, stdin, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
}

// TestRun_OpenCode_PromptLikePayload_StillOnlyDecodesToolArgs proves that
// there is no accidental prompt-blocking path reachable through the
// OpenCode CLI route: an unsupported event name errors out rather than
// being interpreted as a prompt.
func TestRun_OpenCode_UnsupportedEvent_ExitsOne(t *testing.T) {
	stdin := strings.NewReader(`{"event": "prompt.submit", "args": {}}`)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"opencode"}, stdin, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
}
