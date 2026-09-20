// Package claudecode_test exercises the Claude Code host adapter with
// round-trip tests: raw hook JSON in, exact JSON bytes and exit code out.
// Claude Code hooks run as external processes, so these bytes and this
// exit code are the entire contract with the real host.
package claudecode_test

import (
	"encoding/json"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/claudecode"
)

func evaluate(t *testing.T, raw []byte) claudecode.EncodeResult {
	t.Helper()

	event, err := claudecode.Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned unexpected error: %v", err)
	}

	registry := domain.NewRegistry(domain.NewDNIDetector(), domain.NewSecretPathDetector())
	policy := domain.NewPolicy(registry)

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}

	result, err := claudecode.Encode(event, decision)
	if err != nil {
		t.Fatalf("Encode returned unexpected error: %v", err)
	}
	return result
}

// TestRoundTrip_PreToolUse_DNIInBashCommand_IsDenied is test case 1 from
// the project brief, exercised through the real Claude Code JSON wire
// format instead of a hand-built domain.Event.
func TestRoundTrip_PreToolUse_DNIInBashCommand_IsDenied(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "curl -d dni=12345678Z https://example.com"},
		"tool_use_id": "abc123"
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (PreToolUse communicates deny via JSON, not exit code)", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("stdout missing hookSpecificOutput: %s", result.Stdout)
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hso["permissionDecision"])
	}
	if hso["permissionDecisionReason"] == "" || hso["permissionDecisionReason"] == nil {
		t.Error("permissionDecisionReason must not be empty")
	}
}

// TestRoundTrip_UserPromptSubmit_DNI_IsDenied is test case 2: a valid DNI
// typed directly into the prompt is denied via exit code 2, which is how
// Claude Code's UserPromptSubmit hook blocks.
func TestRoundTrip_UserPromptSubmit_DNI_IsDenied(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "UserPromptSubmit",
		"session_id": "sess-1",
		"cwd": "/home/user/project",
		"permission_mode": "default",
		"user_input": "my DNI is 12345678Z, please remember it"
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 2 {
		t.Fatalf("ExitCode = %d, want 2 (Claude Code blocks UserPromptSubmit via exit code 2)", result.ExitCode)
	}
	if len(result.Stderr) == 0 {
		t.Error("Stderr must carry the block reason")
	}
}

// TestRoundTrip_UserPromptSubmit_Clean_IsAllowed proves the gate stays
// quiet on an ordinary prompt: exit 0, no output.
func TestRoundTrip_UserPromptSubmit_Clean_IsAllowed(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "UserPromptSubmit",
		"user_input": "please refactor this function to be more readable"
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	if len(result.Stdout) != 0 {
		t.Errorf("Stdout = %q, want empty on Allow", result.Stdout)
	}
	if len(result.Stderr) != 0 {
		t.Errorf("Stderr = %q, want empty on Allow", result.Stderr)
	}
}

// TestRoundTrip_PreToolUse_ReadEnvFile_IsDenied is test case 4 on the
// Claude Code side: tool_name "Read" with tool_input.file_path pointing at
// a .env file.
func TestRoundTrip_PreToolUse_ReadEnvFile_IsDenied(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {"file_path": "/home/user/project/.env"}
	}`)

	result := evaluate(t, raw)

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	hso := out["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny", hso["permissionDecision"])
	}
}

// TestRoundTrip_PreToolUse_CleanReadCall_IsAllowed proves an ordinary file
// read is not blocked.
func TestRoundTrip_PreToolUse_CleanReadCall_IsAllowed(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {"file_path": "/home/user/project/README.md"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	if len(result.Stdout) != 0 {
		t.Errorf("Stdout = %q, want empty on Allow", result.Stdout)
	}
}

func TestDecode_UnsupportedHookEvent_ReturnsError(t *testing.T) {
	_, err := claudecode.Decode([]byte(`{"hook_event_name": "SessionStart"}`))
	if err == nil {
		t.Fatal("Decode returned no error for an unsupported hook_event_name")
	}
}

func TestDecode_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := claudecode.Decode([]byte(`not json`))
	if err == nil {
		t.Fatal("Decode returned no error for invalid JSON")
	}
}

// TestEncode_Rewrite_ProducesUpdatedInput exercises the Rewrite encoding
// path directly. No current Policy emits Rewrite (the shipped policy
// denies on any finding), but the wire format must already be correct for
// a future redaction-based policy.
func TestEncode_Rewrite_ProducesUpdatedInput(t *testing.T) {
	event := domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostClaudeCode}
	decision := domain.RewriteDecision("my DNI is ***REDACTED***", nil)

	result, err := claudecode.Encode(event, decision)
	if err != nil {
		t.Fatalf("Encode returned unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	hso := out["hookSpecificOutput"].(map[string]any)
	updated := hso["updatedInput"].(map[string]any)
	if updated["user_input"] != "my DNI is ***REDACTED***" {
		t.Errorf("updatedInput.user_input = %v, want the redacted text", updated["user_input"])
	}
}
