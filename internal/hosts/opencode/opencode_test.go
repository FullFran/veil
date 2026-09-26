// Package opencode_test exercises the OpenCode host adapter with
// round-trip tests: raw shim JSON in, exact JSON bytes and exit code out.
//
// Prompt-level, tool-output, history and system-prompt events are all
// covered here now: T1's spike (see downstream harness's
// integration notes) verified that OpenCode's chat.message,
// tool.execute.after, experimental.chat.messages.transform and
// experimental.chat.system.transform hooks can all enforce a real
// decision by mutation, correcting an earlier assumption that OpenCode
// had no prompt-level hook and an unverified claim about
// tool.execute.after.
package opencode_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/opencode"
)

func evaluate(t *testing.T, raw []byte) opencode.EncodeResult {
	t.Helper()

	event, err := opencode.Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned unexpected error: %v", err)
	}

	registry := domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewSecretPathDetector(),
		domain.NewBinaryContentDetector(),
	)
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}

	result, err := opencode.Encode(decision)
	if err != nil {
		t.Fatalf("Encode returned unexpected error: %v", err)
	}
	return result
}

// TestRoundTrip_ToolExecuteBefore_DNIInArgs_IsRewritten is test case 1 on
// the OpenCode side: a DNI in a tool call's arguments is a rewritable
// finding, so the call proceeds with the DNI replaced by a pseudonym
// token instead of being denied outright.
func TestRoundTrip_ToolExecuteBefore_DNIInArgs_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"event": "tool.execute.before",
		"sessionID": "ses-1",
		"tool": "bash",
		"args": {"command": "curl -d dni=12345678Z https://example.com"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a rewrite lets the call proceed)", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	if out["action"] != "rewrite" {
		t.Errorf("action = %v, want rewrite", out["action"])
	}
	args, ok := out["args"].(map[string]any)
	if !ok {
		t.Fatalf("stdout missing args on rewrite: %s", result.Stdout)
	}
	command, _ := args["command"].(string)
	if command == "" || command == "curl -d dni=12345678Z https://example.com" {
		t.Errorf("args.command = %q, want the command with the DNI replaced by a pseudonym token", command)
	}
}

// TestRoundTrip_ToolExecuteBefore_ReadEnvFile_IsDenied is test case 4 on
// the OpenCode side, using the shim's own field shape for the read tool
// (tool: "read", args.filePath).
func TestRoundTrip_ToolExecuteBefore_ReadEnvFile_IsDenied(t *testing.T) {
	raw := []byte(`{
		"event": "tool.execute.before",
		"tool": "read",
		"args": {"filePath": "/home/user/project/.env"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	if out["action"] != "deny" {
		t.Errorf("action = %v, want deny", out["action"])
	}
}

// TestRoundTrip_ToolExecuteBefore_CleanCall_IsAllowed proves the gate
// stays quiet on an ordinary tool call.
func TestRoundTrip_ToolExecuteBefore_CleanCall_IsAllowed(t *testing.T) {
	raw := []byte(`{
		"event": "tool.execute.before",
		"tool": "read",
		"args": {"filePath": "/home/user/project/README.md"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	if out["action"] != "allow" {
		t.Errorf("action = %v, want allow", out["action"])
	}
}

func TestDecode_UnsupportedEvent_ReturnsError(t *testing.T) {
	_, err := opencode.Decode([]byte(`{"event": "some.other.event", "tool": "read", "args": {}}`))
	if err == nil {
		t.Fatal("Decode returned no error for an unsupported event")
	}
}

func TestDecode_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := opencode.Decode([]byte(`not json`))
	if err == nil {
		t.Fatal("Decode returned no error for invalid JSON")
	}
}

// TestEncode_Rewrite_ProducesArgs exercises the Rewrite encoding path
// directly, independent of Policy.
func TestEncode_Rewrite_ProducesArgs(t *testing.T) {
	decision := domain.RewriteDecision("", map[string]string{"filePath": "***REDACTED***"})

	result, err := opencode.Encode(decision)
	if err != nil {
		t.Fatalf("Encode returned unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a rewrite lets the call proceed)", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if out["action"] != "rewrite" {
		t.Errorf("action = %v, want rewrite", out["action"])
	}
	args := out["args"].(map[string]any)
	if args["filePath"] != "***REDACTED***" {
		t.Errorf("args.filePath = %v, want the redacted value", args["filePath"])
	}
}

// TestRoundTrip_ChatMessage_DNIInPrompt_IsRewritten proves veil now
// enforces prompt-level rewriting on OpenCode via chat.message, verified
// in T1 to actually reach the model.
func TestRoundTrip_ChatMessage_DNIInPrompt_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"event": "chat.message",
		"sessionID": "ses-1",
		"fields": {"0": "my DNI is 12345678Z, remember it"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a rewrite lets the message proceed)", result.ExitCode)
	}
	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if out["action"] != "rewrite" {
		t.Fatalf("action = %v, want rewrite", out["action"])
	}
	args := out["args"].(map[string]any)
	got, _ := args["0"].(string)
	if got == "" || got == "my DNI is 12345678Z, remember it" {
		t.Errorf("args[0] = %q, want the DNI replaced by a pseudonym token", got)
	}
}

// TestRoundTrip_ToolExecuteAfter_DNIInOutput_IsRewritten proves veil
// redacts a tool's output via mutation (never via throw, which T1 proved
// does not block anything in tool.execute.after).
func TestRoundTrip_ToolExecuteAfter_DNIInOutput_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"event": "tool.execute.after",
		"sessionID": "ses-1",
		"tool": "bash",
		"fields": {"output": "client DNI on file: 12345678Z"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a rewrite lets the output proceed, redacted)", result.ExitCode)
	}
	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if out["action"] != "rewrite" {
		t.Fatalf("action = %v, want rewrite", out["action"])
	}
	args := out["args"].(map[string]any)
	got, _ := args["output"].(string)
	if got == "" || got == "client DNI on file: 12345678Z" {
		t.Errorf("args.output = %q, want the DNI replaced by a pseudonym token", got)
	}
}

// TestRoundTrip_ToolExecuteAfter_BinaryOutput_IsDenied proves unscannable
// tool output is denied rather than passed through. The fixture uses a
// long base64 blob rather than literal invalid UTF-8 bytes: JSON strings
// cannot carry invalid UTF-8 at all (the wire format itself would reject
// or replace it), so a base64-encoded attachment is the realistic shape
// "binary content" actually takes by the time it reaches veil as a JSON
// field value.
func TestRoundTrip_ToolExecuteAfter_BinaryOutput_IsDenied(t *testing.T) {
	blob := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", 4)
	raw, err := json.Marshal(map[string]any{
		"event":     "tool.execute.after",
		"sessionID": "ses-1",
		"tool":      "read",
		"fields":    map[string]string{"output": blob},
	})
	if err != nil {
		t.Fatalf("failed to build fixture: %v", err)
	}

	result := evaluate(t, raw)

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	if out["action"] != "deny" {
		t.Fatalf("action = %v, want deny", out["action"])
	}
}

// TestRoundTrip_MessagesTransform_DNIInHistory_IsRewritten proves veil
// redacts a DNI resurfacing in conversation history (e.g. a previous
// turn's tool result) before it is resent to the model.
func TestRoundTrip_MessagesTransform_DNIInHistory_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"event": "experimental.chat.messages.transform",
		"sessionID": "ses-1",
		"fields": {"0:0:text": "please remember 12345678Z"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if out["action"] != "rewrite" {
		t.Fatalf("action = %v, want rewrite", out["action"])
	}
	args := out["args"].(map[string]any)
	got, _ := args["0:0:text"].(string)
	if got == "" || got == "please remember 12345678Z" {
		t.Errorf("args[0:0:text] = %q, want the DNI replaced by a pseudonym token", got)
	}
}

// TestRoundTrip_SystemTransform_DNIInSystemPrompt_IsRewritten proves veil
// redacts a DNI accidentally embedded in a system prompt string.
func TestRoundTrip_SystemTransform_DNIInSystemPrompt_IsRewritten(t *testing.T) {
	raw := []byte(`{
		"event": "experimental.chat.system.transform",
		"sessionID": "ses-1",
		"fields": {"0": "client reference 12345678Z"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if out["action"] != "rewrite" {
		t.Fatalf("action = %v, want rewrite", out["action"])
	}
}

func TestDecode_ChatMessage_UnsupportedFieldsOmitted_StillDecodes(t *testing.T) {
	event, err := opencode.Decode([]byte(`{"event": "chat.message", "sessionID": "s", "fields": {}}`))
	if err != nil {
		t.Fatalf("Decode returned unexpected error: %v", err)
	}
	if event.Kind != domain.EventPromptSubmit {
		t.Errorf("Kind = %v, want EventPromptSubmit", event.Kind)
	}
	if event.Host != domain.HostOpenCode {
		t.Errorf("Host = %v, want HostOpenCode", event.Host)
	}
	if event.SessionID != "s" {
		t.Errorf("SessionID = %q, want %q", event.SessionID, "s")
	}
}
