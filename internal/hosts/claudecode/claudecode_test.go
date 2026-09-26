// Package claudecode_test exercises the Claude Code host adapter with
// round-trip tests: raw hook JSON in, exact JSON bytes and exit code out.
// Claude Code hooks run as external processes, so these bytes and this
// exit code are the entire contract with the real host.
package claudecode_test

import (
	"encoding/json"
	"strings"
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
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

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

// TestRoundTrip_PreToolUse_DNIInBashCommand_IsRewritten is test case 1
// from the project brief, exercised through the real Claude Code JSON
// wire format instead of a hand-built domain.Event. A DNI is a rewritable
// finding: Claude Code lets the call proceed with the DNI replaced by a
// pseudonym token, communicated via updatedInput.
func TestRoundTrip_PreToolUse_DNIInBashCommand_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "PreToolUse",
		"session_id": "sess-1",
		"tool_name": "Bash",
		"tool_input": {"command": "curl -d dni=12345678Z https://example.com"},
		"tool_use_id": "abc123"
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (PreToolUse communicates rewrite via JSON, not exit code)", result.ExitCode)
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
	updated, ok := hso["updatedInput"].(map[string]any)
	if !ok {
		t.Fatalf("stdout missing hookSpecificOutput.updatedInput: %s", result.Stdout)
	}
	command, _ := updated["command"].(string)
	if command == "" || command == "curl -d dni=12345678Z https://example.com" {
		t.Errorf("updatedInput.command = %q, want the command with the DNI replaced by a pseudonym token", command)
	}
}

// TestRoundTrip_UserPromptSubmit_DNI_IsRewritten is test case 2: a valid
// DNI typed directly into the prompt is a rewritable finding, so Claude
// Code's UserPromptSubmit hook rewrites it (exit 0, updatedInput) instead
// of blocking it outright.
func TestRoundTrip_UserPromptSubmit_DNI_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"hook_event_name": "UserPromptSubmit",
		"session_id": "sess-1",
		"cwd": "/home/user/project",
		"permission_mode": "default",
		"user_input": "my DNI is 12345678Z, please remember it"
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a rewrite lets the prompt proceed)", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	hso := out["hookSpecificOutput"].(map[string]any)
	updated := hso["updatedInput"].(map[string]any)
	userInput, _ := updated["user_input"].(string)
	if userInput == "" || strings.Contains(userInput, "12345678Z") {
		t.Errorf("updatedInput.user_input = %q, still contains the original DNI", userInput)
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
// path directly, independent of Policy.
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
