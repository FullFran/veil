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
	"github.com/FullFran/veil/internal/problem"
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

	result, err := opencode.Encode(event, decision)
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

	if result.ExitCode != problem.ExitDecision {
		t.Fatalf("ExitCode = %d, want %d (a deny is a decision; the action is in stdout)", result.ExitCode, problem.ExitDecision)
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

	result, err := opencode.Encode(domain.Event{}, decision)
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

func evaluateWith(t *testing.T, policy *domain.Policy, raw []byte) map[string]any {
	t.Helper()
	event, err := opencode.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	result, err := opencode.Encode(event, decision)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (%s)", err, result.Stdout)
	}
	return out
}

// TestRoundTrip_ToolExecuteBefore_NestedArgs_KeepShape proves a rewrite
// answers with the tool's own argument shape: a nested array stays an
// array with its strings masked in place, and a number stays a number.
// v0.1.0 flattened every argument with %v, so the plugin wrote back
// "[map[...]]" and "50" (HagaHarness R8-48).
func TestRoundTrip_ToolExecuteBefore_NestedArgs_KeepShape(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewDNIDetector(), domain.NewSecretPathDetector()), domain.NewMemoryPseudonymStore())
	out := evaluateWith(t, policy, []byte(`{"event":"tool.execute.before","sessionID":"s1","tool":"grep",
		"args":{"pattern":"12345678Z","limit":50,"filters":[{"text":"dni 12345678Z","exact":true}]}}`))

	if out["action"] != "rewrite" {
		t.Fatalf("action = %v, want rewrite (%v)", out["action"], out)
	}
	args := out["args"].(map[string]any)
	if args["pattern"] != "[DNI-001]" {
		t.Errorf("args.pattern = %v, want [DNI-001]", args["pattern"])
	}
	if args["limit"] != float64(50) {
		t.Errorf("args.limit = %#v, want the number 50", args["limit"])
	}
	filters, ok := args["filters"].([]any)
	if !ok || len(filters) != 1 {
		t.Fatalf("args.filters = %#v, want an array of one object", args["filters"])
	}
	filter := filters[0].(map[string]any)
	if filter["text"] != "dni [DNI-001]" || filter["exact"] != true {
		t.Errorf("args.filters[0] = %#v, want text masked in place and exact kept true", filter)
	}
}

// TestRoundTrip_MultiEdit_NestedTokens_AreRehydratedInPlace proves a write
// tool with nested edits gets the real value back inside each edit.
func TestRoundTrip_MultiEdit_NestedTokens_AreRehydratedInPlace(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewDNIDetector(), domain.NewSecretPathDetector()), domain.NewMemoryPseudonymStore())
	evaluateWith(t, policy, []byte(`{"event":"chat.message","sessionID":"s1","fields":{"0":"mi dni es 12345678Z"}}`))

	out := evaluateWith(t, policy, []byte(`{"event":"tool.execute.before","sessionID":"s1","tool":"multiedit",
		"args":{"filePath":"/tmp/ficha.md","edits":[{"oldString":"DNI: ?","newString":"DNI: [DNI-001]","replaceAll":false}]}}`))

	args, ok := out["args"].(map[string]any)
	if !ok {
		t.Fatalf("no args in %v", out)
	}
	edits, ok := args["edits"].([]any)
	if !ok || len(edits) != 1 {
		t.Fatalf("args.edits = %#v, want an array of one edit", args["edits"])
	}
	edit := edits[0].(map[string]any)
	if edit["newString"] != "DNI: 12345678Z" || edit["replaceAll"] != false {
		t.Errorf("edit = %#v, want newString rehydrated and replaceAll kept false", edit)
	}
}

func encodeRaw(t *testing.T, policy *domain.Policy, raw []byte) string {
	t.Helper()
	event, err := opencode.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	result, err := opencode.Encode(event, decision)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return string(result.Stdout)
}

// TestRoundTrip_DottedKey_DoesNotHideANestedValue proves a top-level key
// with a dot ("a.b") and a nested one (a -> b) are scanned and rebuilt
// apart: a shared path let one value skip the scan and leak.
func TestRoundTrip_DottedKey_DoesNotHideANestedValue(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewPhoneDetector()), domain.NewMemoryPseudonymStore())
	for i := 0; i < 8; i++ {
		out := evaluateWith(t, policy, []byte(`{"event":"tool.execute.before","sessionID":"s1","tool":"bash",
			"args":{"a.b":"612 345 678","a":{"b":"hello"}}}`))
		if out["action"] != "rewrite" {
			t.Fatalf("action = %v, want rewrite (%v)", out["action"], out)
		}
		args := out["args"].(map[string]any)
		if args["a.b"] != "[TEL-001]" {
			t.Errorf("args[a.b] = %v, want [TEL-001]", args["a.b"])
		}
		if nested := args["a"].(map[string]any); nested["b"] != "hello" {
			t.Errorf("args.a.b = %v, want hello untouched", nested["b"])
		}
	}
}

// TestRoundTrip_NumericPhone_IsDetected proves a phone sent as a JSON
// number is scanned by its digits, not by Go's float form (6.12345678e+08).
func TestRoundTrip_NumericPhone_IsDetected(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewPhoneDetector()), domain.NewMemoryPseudonymStore())
	out := evaluateWith(t, policy, []byte(`{"event":"tool.execute.before","sessionID":"s1","tool":"bash","args":{"count":612345678}}`))
	if out["action"] != "rewrite" {
		t.Fatalf("action = %v, want rewrite (%v)", out["action"], out)
	}
	if args := out["args"].(map[string]any); args["count"] != "[TEL-001]" {
		t.Errorf("args.count = %v, want [TEL-001]", args["count"])
	}
}

// TestRoundTrip_LargeInteger_KeepsItsDigits proves a rewrite does not
// round an unrelated integer argument through float64.
func TestRoundTrip_LargeInteger_KeepsItsDigits(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(domain.NewDNIDetector()), domain.NewMemoryPseudonymStore())
	stdout := encodeRaw(t, policy, []byte(`{"event":"tool.execute.before","sessionID":"s1","tool":"bash",
		"args":{"id":1234567890123456789,"ratio":0.1,"t":"12345678Z"}}`))
	for _, want := range []string{`"id":1234567890123456789`, `"ratio":0.1`, `"t":"[DNI-001]"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout %s lacks %s", stdout, want)
		}
	}
}

// TestFailureExitCode_BlocksTheEvent pins the exit code this host must
// see for veil to fail closed: the shim blocks on any nonzero exit.
func TestFailureExitCode_BlocksTheEvent(t *testing.T) {
	if opencode.FailureExitCode != problem.ExitFailedClosed {
		t.Fatalf("FailureExitCode = %d, want %d", opencode.FailureExitCode, problem.ExitFailedClosed)
	}
	if opencode.FailureExitCode == problem.ExitDecision {
		t.Fatal("a failure must never exit with the decision class")
	}
}
