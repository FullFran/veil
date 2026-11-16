package v0_1

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/problem"
)

// secretDNI stands for personal data a detector finds wherever it is.
const secretDNI = "12345678Z"

// pseudonymizingGuard rewrites secretDNI in every field it appears in, as
// the policy does: the substitution reaches every field of the event.
func pseudonymizingGuard(e domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
	if !strings.Contains(e.Text, secretDNI) {
		return domain.AllowDecision(), evidence, ""
	}
	fields := make(map[string]string, len(e.Fields))
	for k, v := range e.Fields {
		fields[k] = strings.ReplaceAll(v, secretDNI, "[DNI-001]")
	}
	return domain.RewriteDecision(strings.ReplaceAll(e.Text, secretDNI, "[DNI-001]"), fields), evidence, ""
}

// applyDecision is the request the Observed Agent goes on with after a
// result: nothing on deny, the request itself on allow, and on modify the
// request with parameter_overrides (steps/toolCallRequest arguments) and
// redactions (JSON pointers into the payload) applied.
func applyDecision(t *testing.T, request []byte, result map[string]any) any {
	t.Helper()
	var req map[string]any
	if err := json.Unmarshal(request, &req); err != nil {
		t.Fatal(err)
	}
	switch result["decision"] {
	case "deny":
		return nil
	case "allow":
		return req
	case "modify":
	default:
		t.Fatalf("decision = %v, want allow, deny or modify", result["decision"])
	}
	params := req["params"].(map[string]any)
	payload := params["payload"].(map[string]any)
	mods := result["modifications"].(map[string]any)
	if overrides, ok := mods["parameter_overrides"].(map[string]any); ok {
		args := payload["arguments"].(map[string]any)
		for name, value := range overrides {
			arg, ok := args[name].(map[string]any)
			if !ok {
				t.Fatalf("parameter_overrides names %q, not an argument", name)
			}
			arg["value"] = value
		}
	}
	redactions, _ := mods["redactions"].([]any)
	for _, r := range redactions {
		r := r.(map[string]any)
		setPointer(t, payload, r["path"].(string), r["replacement"])
	}
	return req
}

func setPointer(t *testing.T, doc any, pointer string, value any) {
	t.Helper()
	tokens := strings.Split(pointer, "/")[1:]
	for i, tok := range tokens {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		last := i == len(tokens)-1
		switch d := doc.(type) {
		case map[string]any:
			if _, ok := d[tok]; !ok {
				t.Fatalf("redaction %s addresses no member %q", pointer, tok)
			}
			if last {
				d[tok] = value
				return
			}
			doc = d[tok]
		case []any:
			n, err := strconv.Atoi(tok)
			if err != nil || n < 0 || n >= len(d) {
				t.Fatalf("redaction %s addresses no item %q", pointer, tok)
			}
			if last {
				d[n] = value
				return
			}
			doc = d[n]
		default:
			t.Fatalf("redaction %s goes through a leaf", pointer)
		}
	}
}

// leaks reports whether s appears in any string leaf or member name of v.
func leaks(v any, s string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if strings.Contains(k, s) || leaks(child, s) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if leaks(child, s) {
				return true
			}
		}
	case string:
		return strings.Contains(t, s)
	case float64:
		return strings.Contains(strconv.FormatFloat(t, 'f', -1, 64), s)
	}
	return false
}

// TestAnswer_PersonalDataAnywhereInParams_NeverPassesInClear places a DNI
// in every position of params the brief found unscanned (fields, extra
// members, member names, the tool name, the raw command, metadata): veil
// must either redact it where ACS can express that or deny the step.
func TestAnswer_PersonalDataAnywhereInParams_NeverPassesInClear(t *testing.T) {
	d := secretDNI
	cases := []struct {
		name, method, payload string
		metadata              string
		wantDeny              bool
	}{
		{"raw_command", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{"command":{"value":"ls"}},"raw_command":"echo ` + d + `"}`, "", true},
		{"intent.description", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{},"intent":{"description":"dni ` + d + `"}}`, "", false},
		{"intent.goal", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{},"intent":{"goal":"dni ` + d + `"}}`, "", false},
		{"operation", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{},"operation":"` + d + `"}`, "", false},
		{"capability", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{},"capability":"` + d + `"}`, "", false},
		{"extra property", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{},"note":{"text":"` + d + `"}}`, "", false},
		{"argument name", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{"` + d + `":{"value":"x"}}}`, "", true},
		{"nested argument value", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{"opts":{"value":{"who":["` + d + `"]}}}}`, "", false},
		{"argument provenance", methodToolRequest, `{"tool":{"name":"Bash"},"arguments":{"a":{"value":"x","note":"` + d + `"}}}`, "", false},
		{"tool.name", methodToolRequest, `{"tool":{"name":"` + d + `"},"arguments":{}}`, "", true},
		{"tool.provider", methodToolRequest, `{"tool":{"name":"Bash","provider":"` + d + `"},"arguments":{}}`, "", false},
		{"user message extra member", methodUserMessage, `{"content":[{"type":"text","value":"hola","note":"` + d + `"}]}`, "", false},
		{"user message member name", methodUserMessage, `{"content":[{"type":"text","value":{"` + d + `":"x"}}]}`, "", true},
		{"knowledge query", methodKnowledge, `{"query":{"value":"` + d + `"},"results":[]}`, "", false},
		{"knowledge source_id", methodKnowledge, `{"query":{"value":"q"},"results":[{"value":"x","source_id":"` + d + `"}]}`, "", false},
		{"memory query", methodMemoryRetrieval, `{"query":{"value":"` + d + `"},"results":[]}`, "", false},
		{"memory_id", methodMemoryRetrieval, `{"results":[{"value":"x","memory_id":"` + d + `"}]}`, "", false},
		{"intent.parsed resource", methodAgentTrigger, `{"trigger_type":"user_message","intent":{"parsed":[{"resource":"` + d + `"}],"parser_provenance":{"origin":"system","provenance_id":"p-1"}}}`, "", false},
		{"tool result operation", methodToolResult, `{"tool":{"name":"Bash"},"exit_status":"success","outputs":[],"operation":"` + d + `"}`, "", false},
		{"tool result tool.name", methodToolResult, `{"tool":{"name":"` + d + `"},"exit_status":"success","outputs":[]}`, "", true},
		{"metadata member", methodUserMessage, `{"content":[{"type":"text","value":"hola"}]}`, `,"user":"` + d + `"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"jsonrpc":"2.0","id":"1","method":"` + tc.method + `","params":{"acs_version":"0.1.0",` +
				`"request_id":"1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f","timestamp":"2026-09-09T14:02:11Z",` +
				`"metadata":{"agent_id":"a","session_id":"5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"` + tc.metadata + `},"payload":` + tc.payload + `}}`)
			if ref := validateRequest(raw); ref != nil {
				t.Fatalf("fixture is off the pinned schema: %+v", ref)
			}
			reply := newAt(readmeTime, pseudonymizingGuard, nil).Answer(raw)
			if strings.Contains(string(reply.Body), d) {
				t.Fatalf("the response carries the DNI: %s", reply.Body)
			}
			r := result(t, reply.Body)
			if tc.wantDeny {
				assertFailureDeny(t, reply.Body, problem.ACSUnredactable)
				return
			}
			if r["decision"] != "modify" {
				t.Fatalf("decision = %v, want modify: %s", r["decision"], reply.Body)
			}
			if effective := applyDecision(t, raw, r); leaks(effective, d) {
				t.Fatalf("the request the agent goes on with still carries the DNI: %v", effective)
			}
		})
	}
}

// TestDecodeHook_ScansEveryLeafAndMemberName_ButTheStructuralFields names
// each scanned field by its JSON pointer under params and each member
// name by "key " and its pointer, and leaves out only what veil itself
// needs: acs_version, request_id, timestamp, signature and session_id.
func TestDecodeHook_ScansEveryLeafAndMemberName_ButTheStructuralFields(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":"1","method":"steps/toolCallResult","params":{"acs_version":"0.1.0",` +
		`"request_id":"1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f","timestamp":"2026-09-09T14:02:11Z",` +
		`"metadata":{"session_id":"5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22","agent_id":"bot"},` +
		`"payload":{"tool":{"name":"Bash"},"exit_status":"success","outputs":[{"value":{"a/b":7}}],"duration_ms":3}}}`)
	env, ref := decodeEnvelope(raw)
	if ref != nil {
		t.Fatalf("decodeEnvelope refused: %+v", ref)
	}
	h, ref := decodeHook(env)
	if ref != nil {
		t.Fatalf("decodeHook refused: %+v", ref)
	}
	want := map[string]string{
		"/metadata/agent_id":                "bot",
		"/payload/tool/name":                "Bash",
		"/payload/exit_status":              "success",
		"/payload/outputs/0/value/a~1b":     "7",
		"/payload/duration_ms":              "3",
		"key /payload/outputs/0/value/a~1b": "a/b",
		"key /metadata/agent_id":            "agent_id",
		"key /metadata/session_id":          "session_id",
	}
	for name, value := range want {
		if got, ok := h.event.Fields[name]; !ok || got != value {
			t.Errorf("Fields[%q] = %q, %v, want %q", name, got, ok, value)
		}
	}
	for _, structural := range []string{"/acs_version", "/request_id", "/timestamp", "/metadata/session_id"} {
		if _, ok := h.event.Fields[structural]; ok {
			t.Errorf("Fields has the structural field %s", structural)
		}
	}
}
