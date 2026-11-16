package v0_1

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/problem"
)

const contextSession = "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"

// hookRequest is a request for method with payload, stamped readmeTime.
func hookRequest(t *testing.T, method string, payload map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": method,
		"params": map[string]any{
			"acs_version": "0.1.0",
			"request_id":  "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
			"timestamp":   readmeTime.Format(time.RFC3339),
			"metadata":    map[string]any{"agent_id": "a", "session_id": contextSession},
			"payload":     payload,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// contextHook is one ACS hook whose payload carries text that enters the
// model's context, with the event veil evaluates for it and where a
// rewrite of its first field lands in the payload.
type contextHook struct {
	method  string
	payload map[string]any
	event   domain.Event
	field   string // the field the rewrite changes
	pointer string // where that rewrite lands in the payload
}

func contextHooks() []contextHook {
	return []contextHook{
		{
			method: "steps/userMessage",
			payload: map[string]any{"content": []any{
				map[string]any{"type": "text", "value": "My DNI is 12345678Z"},
				map[string]any{"type": "text", "value": "thanks"},
			}},
			event: domain.Event{
				Kind: domain.EventPromptSubmit, Host: domain.HostACS, SessionID: contextSession,
				Text:   "content.0: My DNI is 12345678Z\ncontent.1: thanks\n",
				Fields: map[string]string{"content.0": "My DNI is 12345678Z", "content.1": "thanks"},
			},
			field: "content.0", pointer: "/content/0/value",
		},
		{
			method: "steps/agentTrigger",
			payload: map[string]any{
				"trigger_type":   "a2a_inbound",
				"trigger_source": map[string]any{"peer": "agent-b", "message": "Call 600123456"},
				"intent":         map[string]any{"raw": "book a table", "parsed": []any{map[string]any{"tool": "x"}}, "parser_provenance": map[string]any{"origin": "system", "provenance_id": "p-1"}},
			},
			event: domain.Event{
				Kind: domain.EventPromptSubmit, Host: domain.HostACS, SessionID: contextSession,
				Text: "intent.raw: book a table\ntrigger_source.message: Call 600123456\ntrigger_source.peer: agent-b\n",
				Fields: map[string]string{
					"intent.raw":             "book a table",
					"trigger_source.message": "Call 600123456",
					"trigger_source.peer":    "agent-b",
				},
			},
			field: "trigger_source.message", pointer: "/trigger_source/message",
		},
		{
			method: "steps/knowledgeRetrieval",
			payload: map[string]any{
				"query":   map[string]any{"value": "customer record"},
				"source":  map[string]any{"name": "crm", "type": "vector_db"},
				"results": []any{map[string]any{"value": map[string]any{"name": "Ana", "dni": "12345678Z"}, "source_id": "doc-1", "score": 0.9}},
			},
			event: domain.Event{
				Kind: domain.EventToolOutput, Host: domain.HostACS, SessionID: contextSession, ToolName: "knowledgeRetrieval",
				Text:   "results.0.dni: 12345678Z\nresults.0.name: Ana\n",
				Fields: map[string]string{"results.0.dni": "12345678Z", "results.0.name": "Ana"},
			},
			field: "results.0.dni", pointer: "/results/0/value/dni",
		},
		{
			method: "steps/memoryContextRetrieval",
			payload: map[string]any{
				"query":   map[string]any{"value": "user preferences"},
				"results": []any{map[string]any{"memory_id": "m-1", "value": "Lives at Calle Mayor 1"}},
			},
			event: domain.Event{
				Kind: domain.EventToolOutput, Host: domain.HostACS, SessionID: contextSession, ToolName: "memoryContextRetrieval",
				Text:   "results.0: Lives at Calle Mayor 1\n",
				Fields: map[string]string{"results.0": "Lives at Calle Mayor 1"},
			},
			field: "results.0", pointer: "/results/0/value",
		},
	}
}

// TestDecodeHook_ContextHooks maps every hook whose payload enters the
// model's context to an existing domain event: inbound text to
// PromptSubmit, retrieved text to ToolOutput.
func TestDecodeHook_ContextHooks(t *testing.T) {
	for _, tc := range contextHooks() {
		t.Run(tc.method, func(t *testing.T) {
			env, ref := decodeEnvelope(hookRequest(t, tc.method, tc.payload))
			if ref == nil {
				ref = validatePayload(env)
			}
			if ref != nil {
				t.Fatalf("request refused: %+v", ref)
			}
			h, ref := decodeHook(env)
			if ref != nil {
				t.Fatalf("decodeHook refused: %+v", ref)
			}
			if !reflect.DeepEqual(h.event, tc.event) {
				t.Fatalf("event =\n%#v\nwant\n%#v", h.event, tc.event)
			}
		})
	}
}

// TestAnswer_ContextHooks_EncodeEachDecision answers each context hook
// with allow, deny and a rewrite whose redaction addresses the changed
// value in the payload, every response valid against the pinned schema.
func TestAnswer_ContextHooks_EncodeEachDecision(t *testing.T) {
	for _, tc := range contextHooks() {
		t.Run(tc.method, func(t *testing.T) {
			msg := hookRequest(t, tc.method, tc.payload)
			if r := result(t, newAt(readmeTime, allowGuard, nil).Answer(msg).Body); r["decision"] != "allow" {
				t.Fatalf("allow guard answered %v", r)
			}
			deny := func(domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
				return domain.DenyDecision("no"), evidence, ""
			}
			if r := result(t, newAt(readmeTime, deny, nil).Answer(msg).Body); r["decision"] != "deny" {
				t.Fatalf("deny guard answered %v", r)
			}
			rewrite := func(e domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
				fields := map[string]string{}
				for k, v := range e.Fields {
					fields[k] = v
				}
				fields[tc.field] = "<PSEUDONYM>"
				return domain.RewriteDecision("", fields), evidence, ""
			}
			r := result(t, newAt(readmeTime, rewrite, nil).Answer(msg).Body)
			want := map[string]any{"redactions": []any{map[string]any{"path": tc.pointer, "replacement": "<PSEUDONYM>"}}}
			if r["decision"] != "modify" || !reflect.DeepEqual(r["modifications"], want) {
				t.Fatalf("rewrite answered %v, want modify with %v", r, want)
			}
		})
	}
}

// TestAnswer_ContextHookOffItsSchema_IsInvalidParams validates the new
// hooks' payloads against their pinned schemas.
func TestAnswer_ContextHookOffItsSchema_IsInvalidParams(t *testing.T) {
	cases := map[string]map[string]any{
		"steps/userMessage":            {"content": []any{}},
		"steps/agentTrigger":           {"trigger_type": "telepathy"},
		"steps/knowledgeRetrieval":     {"results": []any{}},
		"steps/memoryContextRetrieval": {"results": "none"},
	}
	for method, payload := range cases {
		t.Run(method, func(t *testing.T) {
			assertError(t, newAt(readmeTime, allowGuard, nil).Answer(hookRequest(t, method, payload)), -32602, problem.ACSRequestInvalid)
		})
	}
}

// TestAnswer_HooksOutsideTheEvaluatedSet_AreUnsupported keeps the hooks
// veil deliberately leaves out (README "Divergences") failing closed.
func TestAnswer_HooksOutsideTheEvaluatedSet_AreUnsupported(t *testing.T) {
	for _, method := range []string{"steps/agentResponse", "steps/sessionStart", "steps/turnStart", "steps/subagentStart", "steps/skillLoad", "steps/memoryStore"} {
		t.Run(method, func(t *testing.T) {
			assertError(t, newAt(readmeTime, allowGuard, nil).Answer(hookRequest(t, method, map[string]any{})), rpcCapabilityNotNegotiated, problem.ACSMethodUnsupported)
		})
	}
}

// TestAnswer_Handshake_DeclaresExactlyTheEvaluatedSet lists every hook
// veil evaluates, in order, when the client implements them all.
func TestAnswer_Handshake_DeclaresExactlyTheEvaluatedSet(t *testing.T) {
	all := []string{
		"steps/agentTrigger", "steps/userMessage", "steps/knowledgeRetrieval", "steps/memoryContextRetrieval",
		"steps/toolCallRequest", "steps/toolCallResult", "steps/agentResponse", "steps/sessionStart",
	}
	var msg map[string]any
	if err := json.Unmarshal(hello(t, []string{"0.1.0"}), &msg); err != nil {
		t.Fatal(err)
	}
	msg["params"].(map[string]any)["payload"].(map[string]any)["methods_implemented"] = all
	raw, _ := json.Marshal(msg)
	r := result(t, newAt(readmeTime, allowGuard, nil).Answer(raw).Body)
	want := `["steps/agentTrigger","steps/userMessage","steps/knowledgeRetrieval","steps/memoryContextRetrieval","steps/toolCallRequest","steps/toolCallResult"]`
	if got, _ := json.Marshal(r["methods_evaluated"]); string(got) != want {
		t.Fatalf("methods_evaluated = %s, want %s", got, want)
	}
}
