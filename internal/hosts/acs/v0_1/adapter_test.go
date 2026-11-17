package v0_1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// katSecret is the ACS specification's example secret (bytes 0..31) the
// testdata/kat files are signed with, under katKeyID.
var katSecret = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

const katKeyID = "2026-11"

// readmeTime is the timestamp of the README examples.
var readmeTime = time.Date(2026, 9, 9, 14, 2, 11, 0, time.UTC)

var evidence = json.RawMessage(`{"specversion":"1.0","type":"test"}`)

func allowGuard(domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
	return domain.AllowDecision(), evidence, ""
}

func newAt(now time.Time, guard port.Guard, secret *port.Secret) port.Version {
	return New(port.Config{Guard: guard, Secret: secret, Now: func() time.Time { return now }})
}

func katSecretConfig() *port.Secret {
	return &port.Secret{KeyID: katKeyID, Bytes: katSecret}
}

// unsignedExample reads a vendored request and drops a placeholder
// signature: the NAT examples carry "<base64 HMAC>", which no secret can
// verify. Real signatures are covered by testdata/kat.
func unsignedExample(t *testing.T, name string) []byte {
	t.Helper()
	raw := readExample(t, name)
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	p := env["params"].(map[string]any)
	sig, ok := p["signature"].(map[string]any)
	if !ok {
		return raw
	}
	if sig["value"] != "<base64 HMAC>" {
		t.Fatalf("%s carries a real signature; sign it in testdata/kat instead", name)
	}
	delete(p, "signature")
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// response decodes a reply body that must validate against the pinned
// response envelope schema.
func response(t *testing.T, body []byte) map[string]any {
	t.Helper()
	if err := validateResponse(body); err != nil {
		t.Fatalf("response does not validate against response-envelope.json: %v\n%s", err, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func result(t *testing.T, body []byte) map[string]any {
	t.Helper()
	m := response(t, body)
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("response has no result: %s", body)
	}
	return r
}

// assertError checks a JSON-RPC error reply: its code, veil's problem code
// in data.reason and data.problem, and the reply's Failure.
func assertError(t *testing.T, reply port.Reply, rpc int, code problem.Code) map[string]any {
	t.Helper()
	m := response(t, reply.Body)
	e, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("response is not an error: %s", reply.Body)
	}
	if got := int(e["code"].(float64)); got != rpc {
		t.Fatalf("error.code = %d, want %d", got, rpc)
	}
	data := e["data"].(map[string]any)
	if data["reason"] != string(code) {
		t.Fatalf("error.data.reason = %v, want %s", data["reason"], code)
	}
	if p := data["problem"].(map[string]any); p["code"] != string(code) || p["type"] != code.Type() {
		t.Fatalf("error.data.problem = %v, want code %s", p, code)
	}
	if reply.Failure != code {
		t.Fatalf("Failure = %q, want %q", reply.Failure, code)
	}
	return data
}

// TestAnswer_VendoredHookExamples_EncodeEachDecisionToASchemaValidResponse
// answers every vendored hook request with each decision veil can reach
// and checks the response against the pinned response envelope schema.
func TestAnswer_VendoredHookExamples_EncodeEachDecisionToASchemaValidResponse(t *testing.T) {
	examples := []string{
		"readme-file-read.request.json",
		"readme-database-query.request.json",
		"in-action-email-send.request.json",
		"nat-tool-call-request.request.json",
		"nat-tool-call-result.request.json",
	}
	rewrite := func(e domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
		fields := map[string]string{}
		for k, v := range e.Fields {
			fields[k] = v
		}
		names := slices.Sorted(maps.Keys(fields))
		for _, k := range names {
			if strings.HasPrefix(k, "/payload/arguments/") || strings.HasPrefix(k, "/payload/outputs/") {
				fields[k] = "<PSEUDONYM_1>"
				break
			}
		}
		return domain.RewriteDecision("", fields), evidence, ""
	}
	deny := func(domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
		return domain.DenyDecision("secret detected"), evidence, ""
	}
	decisions := map[string]port.Guard{"allow": allowGuard, "deny": deny, "modify": rewrite}
	for _, name := range examples {
		raw := unsignedExample(t, name)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				RequestID string `json:"request_id"`
				Timestamp string `json:"timestamp"`
			} `json:"params"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		now, err := time.Parse(time.RFC3339, req.Params.Timestamp)
		if err != nil {
			t.Fatal(err)
		}
		for want, guard := range decisions {
			t.Run(name+"/"+want, func(t *testing.T) {
				reply := newAt(now, guard, nil).Answer(raw)
				if reply.Failure != "" {
					t.Fatalf("Failure = %s, want a decision: %s", reply.Failure, reply.Body)
				}
				m := response(t, reply.Body)
				if got, _ := json.Marshal(m["id"]); !bytes.Equal(got, bytes.TrimSpace(req.ID)) {
					t.Fatalf("id = %s, want %s", got, req.ID)
				}
				r := m["result"].(map[string]any)
				if r["decision"] != want {
					t.Fatalf("decision = %v, want %s", r["decision"], want)
				}
				if r["request_id"] != req.Params.RequestID || r["acs_version"] != Version {
					t.Fatalf("result does not echo the request: %v", r)
				}
				veil := r["policy_data"].(map[string]any)["veil"].(map[string]any)
				if ev := veil["evidence"].(map[string]any); ev["type"] != "test" {
					t.Fatalf("policy_data.veil.evidence = %v, want the guard's record", ev)
				}
			})
		}
	}
}

// TestAnswer_RewriteOfArguments_OverridesOnlyTheChangedArguments maps a
// rewrite of tool arguments to parameter_overrides of the top-level
// arguments that changed, with their full rebuilt value.
func TestAnswer_RewriteOfArguments_OverridesOnlyTheChangedArguments(t *testing.T) {
	guard := func(e domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
		fields := map[string]string{}
		for k, v := range e.Fields {
			fields[k] = v
		}
		fields["/payload/arguments/recipient/value"] = "<EMAIL_1>"
		return domain.RewriteDecision("", fields), evidence, ""
	}
	r := result(t, newAt(time.Date(2026, 4, 30, 10, 30, 0, 0, time.UTC), guard, nil).Answer(readExample(t, "in-action-email-send.request.json")).Body)
	mods := r["modifications"].(map[string]any)
	want := map[string]any{"recipient": "<EMAIL_1>"}
	got, _ := json.Marshal(mods["parameter_overrides"])
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(got, wantJSON) {
		t.Fatalf("parameter_overrides = %s, want %s", got, wantJSON)
	}
	if _, ok := mods["redactions"]; ok {
		t.Fatalf("a rewrite of arguments carries redactions: %v", mods)
	}
}

// TestAnswer_RewriteOfOutputs_RedactsByPointerIntoThePayload maps a
// rewrite of tool output to redactions whose JSON pointer addresses the
// changed output value in the payload.
func TestAnswer_RewriteOfOutputs_RedactsByPointerIntoThePayload(t *testing.T) {
	guard := func(e domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
		return domain.RewriteDecision("", map[string]string{"/payload/outputs/0/value": "<NAME_1>\n"}), evidence, ""
	}
	r := result(t, newAt(time.Date(2026, 11, 3, 9, 39, 8, 0, time.UTC), guard, nil).Answer(unsignedExample(t, "nat-tool-call-result.request.json")).Body)
	want := map[string]any{"redactions": []any{map[string]any{"path": "/outputs/0/value", "replacement": "<NAME_1>\n"}}}
	if !reflect.DeepEqual(r["modifications"], want) {
		t.Fatalf("modifications = %v, want %v", r["modifications"], want)
	}
}

// TestAnswer_NeverEmitsAskDeferOrAnImplicitAllow covers HCS-0005-R014 and
// R015: veil has no human approval channel, so a decision it cannot
// express (Unknown, or a rewrite that changes nothing) and a guard failure
// are answered with deny, never ask, defer or allow.
func TestAnswer_NeverEmitsAskDeferOrAnImplicitAllow(t *testing.T) {
	cases := map[string]struct {
		guard port.Guard
		code  problem.Code
	}{
		"unknown decision": {func(domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
			return domain.Decision{}, evidence, ""
		}, problem.Internal},
		"rewrite that changes nothing": {func(e domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
			return domain.RewriteDecision("", e.Fields), evidence, ""
		}, problem.Internal},
		"guard failure": {func(domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
			return domain.Decision{}, nil, problem.StoreLocked
		}, problem.StoreLocked},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			reply := newAt(readmeTime, tc.guard, nil).Answer(readExample(t, "readme-file-read.request.json"))
			if reply.Failure != tc.code {
				t.Fatalf("Failure = %q, want %q", reply.Failure, tc.code)
			}
			assertFailureDeny(t, reply.Body, tc.code)
		})
	}
}

func assertFailureDeny(t *testing.T, body []byte, code problem.Code) {
	t.Helper()
	r := result(t, body)
	if r["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", r["decision"])
	}
	codes := r["reason_codes"].([]any)
	if len(codes) != 1 || codes[0] != string(code) {
		t.Fatalf("reason_codes = %v, want [%s]", codes, code)
	}
	p := r["policy_data"].(map[string]any)["veil"].(map[string]any)["problem"].(map[string]any)
	if p["code"] != string(code) || p["type"] != code.Type() {
		t.Fatalf("policy_data.veil.problem = %v, want %s", p, code)
	}
}

// TestAnswer_Unavailable_DeniesHooksAndRefusesHandshakes: when veil cannot
// evaluate (for example its policy is invalid), a hook is denied with that
// code and a handshake is refused, so no session starts on a guard that
// would fail open.
func TestAnswer_Unavailable_DeniesHooksAndRefusesHandshakes(t *testing.T) {
	v := New(port.Config{Unavailable: problem.PolicyInvalid, Now: func() time.Time { return readmeTime }})
	reply := v.Answer(readExample(t, "readme-file-read.request.json"))
	if reply.Failure != problem.PolicyInvalid {
		t.Fatalf("Failure = %q, want %q", reply.Failure, problem.PolicyInvalid)
	}
	assertFailureDeny(t, reply.Body, problem.PolicyInvalid)

	assertError(t, v.Answer(hello(t, []string{"0.1.0"})), rpcSessionRefused, problem.PolicyInvalid)
}

func hello(t *testing.T, versions []string) []byte {
	t.Helper()
	msg := map[string]any{
		"jsonrpc": "2.0", "id": "h-1", "method": "handshake/hello",
		"params": map[string]any{
			"acs_version": "0.1.0",
			"request_id":  "9b0c2f7e-3a1d-4c5e-8f60-718293a4b5c6",
			"timestamp":   readmeTime.Format(time.RFC3339),
			"metadata":    map[string]any{"agent_id": "a", "session_id": "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"},
			"payload": map[string]any{
				"acs_versions_supported": versions,
				"methods_implemented":    []string{"steps/toolCallRequest", "steps/userMessage", "steps/agentResponse"},
				"transports_supported":   []string{"stdio"},
				"provenance_producer":    "none",
			},
		},
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestAnswer_Handshake_AnswersAServerHelloThatFailsClosed negotiates 0.1.0,
// evaluates only the hooks veil maps that the client implements, and
// tells the client to deny when a decision fails.
func TestAnswer_Handshake_AnswersAServerHelloThatFailsClosed(t *testing.T) {
	reply := newAt(readmeTime, allowGuard, nil).Answer(hello(t, []string{"0.1.0"}))
	if reply.Failure != "" {
		t.Fatalf("Failure = %s: %s", reply.Failure, reply.Body)
	}
	r := result(t, reply.Body)
	if r["negotiated_version"] != "0.1.0" || r["on_decision_failure"] != "deny" || r["selected_transport"] != "stdio" {
		t.Fatalf("ServerHello = %v", r)
	}
	if got, _ := json.Marshal(r["methods_evaluated"]); string(got) != `["steps/userMessage","steps/toolCallRequest"]` {
		t.Fatalf("methods_evaluated = %s, want only the mapped hooks the client implements", got)
	}
	if got, _ := json.Marshal(r["signature_algorithms_supported"]); string(got) != `[]` {
		t.Fatalf("signature_algorithms_supported = %s, want [] without a secret", got)
	}
}

// TestAnswer_HandshakeWithoutOurVersion_IsUnsupportedVersion lists the
// versions veil speaks in data.supported_versions.
func TestAnswer_HandshakeWithoutOurVersion_IsUnsupportedVersion(t *testing.T) {
	reply := newAt(readmeTime, allowGuard, nil).Answer(hello(t, []string{"0.2.0"}))
	data := assertError(t, reply, rpcUnsupportedVersion, problem.ACSVersionUnsupported)
	if got, _ := json.Marshal(data["supported_versions"]); string(got) != `["0.1.0"]` {
		t.Fatalf("supported_versions = %s", got)
	}
}

// TestAnswer_Ping_AllowsWithoutASignatureEvenWhenOneIsRequired follows the
// system/ping schema: always allow, never a signature requirement.
func TestAnswer_Ping_AllowsWithoutASignatureEvenWhenOneIsRequired(t *testing.T) {
	ping := `{"jsonrpc":"2.0","id":5,"method":"system/ping","params":{"acs_version":"0.1.0","request_id":"1c2d3e4f-5a6b-4c7d-8e9f-a0b1c2d3e4f5","timestamp":"2020-01-01T00:00:00Z","metadata":{"agent_id":"a","session_id":"5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"},"payload":{"echo":"rtt-1"}}}`
	reply := newAt(readmeTime, allowGuard, katSecretConfig()).Answer([]byte(ping))
	if reply.Failure != "" {
		t.Fatalf("Failure = %s: %s", reply.Failure, reply.Body)
	}
	r := result(t, reply.Body)
	if r["decision"] != "allow" {
		t.Fatalf("decision = %v, want allow", r["decision"])
	}
	if p := r["payload"].(map[string]any); p["status"] != "ok" || p["echo"] != "rtt-1" {
		t.Fatalf("payload = %v", p)
	}
}

// TestAnswer_SignedKnownAnswer_VerifiesAndSignsTheResponse verifies
// requests signed outside veil (testdata/kat) and checks the response is
// signed with the request's session key over its JCS form.
func TestAnswer_SignedKnownAnswer_VerifiesAndSignsTheResponse(t *testing.T) {
	cases := map[string]time.Time{
		"readme-file-read.signed.json": readmeTime,
		"jcs-signed.json":              time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC),
	}
	for name, now := range cases {
		t.Run(name, func(t *testing.T) {
			reply := newAt(now, allowGuard, katSecretConfig()).Answer(readKAT(t, name))
			if reply.Failure != "" {
				t.Fatalf("Failure = %s: %s", reply.Failure, reply.Body)
			}
			r := result(t, reply.Body)
			sig := r["signature"].(map[string]any)
			if sig["algorithm"] != "HMAC-SHA256" || sig["key_id"] != katKeyID {
				t.Fatalf("result.signature = %v", sig)
			}
			var req struct {
				Params struct {
					Metadata struct {
						SessionID string `json:"session_id"`
					} `json:"metadata"`
				} `json:"params"`
			}
			if err := json.Unmarshal(readKAT(t, name), &req); err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalize(reply.Body, "result")
			if err != nil {
				t.Fatal(err)
			}
			key, err := deriveKey(katSecret, req.Params.Metadata.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			if want := signatureValue(key, canonical); sig["value"] != want {
				t.Fatalf("result.signature.value = %v, want %s", sig["value"], want)
			}
		})
	}
}

// TestAnswer_FailsClosedWithItsCode covers every refusal: each is a
// JSON-RPC error with the ACS code and veil's problem code, never a
// TestAnswer_FailsClosedWithItsCode covers every refusal. On an evaluated
// hook whose answer can still be formed (a usable id and request_id), the
// refusal is a deny decision: an error carries no decision, and ACS
// handshake.json lets the host apply on_decision_failure, whose default
// is proceed. Elsewhere it stays a JSON-RPC error with its code.
func TestAnswer_FailsClosedWithItsCode(t *testing.T) {
	signed := string(readKAT(t, "readme-file-read.signed.json"))
	unsigned := string(readExample(t, "readme-file-read.request.json"))
	other := &port.Secret{KeyID: "2027-01", Bytes: katSecret}
	value := `"value": "/reports/q3-summary.md"`
	caseVariant := strings.Replace(unsigned, value, `"value": "mi dni 12345678Z", "VALUE": "hola"`, 1)
	cases := []struct {
		name   string
		msg    string
		secret *port.Secret
		now    time.Time
		rpc    int
		code   problem.Code
		deny   bool
	}{
		{"unparseable JSON", `{"jsonrpc":`, nil, readmeTime, port.RPCParseError, problem.InputInvalid, false},
		{"batch", "[" + unsigned + "]", nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, false},
		{"envelope off schema", strings.Replace(unsigned, `"jsonrpc": "2.0"`, `"jsonrpc": "1.0"`, 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"request_id not a uuid", strings.Replace(unsigned, `"b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11"`, `"not-a-uuid"`, 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, false},
		{"payload off schema", strings.Replace(unsigned, `"tool": {`, `"tool": {"version": 3,`, 1), nil, readmeTime, port.RPCInvalidParams, problem.ACSRequestInvalid, true},
		{"member differing only by case", caseVariant, nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"member differing only by case, signed", string(signWith(t, []byte(caseVariant), katSecret, katKeyID)), katSecretConfig(), readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"payload member next to its case variant", strings.Replace(unsigned, `"arguments": {`, `"ARGUMENTS": {"path": {"value": "x"}}, "arguments": {`, 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"duplicate member in the payload", strings.Replace(unsigned, value, value+`, "value": "hola"`, 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"duplicate member at the root", strings.Replace(unsigned, `"id": "1",`, `"id": "1", "id": "2",`, 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, false},
		{"lone surrogate", strings.Replace(unsigned, "/reports/q3-summary.md", `\ud800`, 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"invalid UTF-8", strings.Replace(unsigned, "/reports/q3-summary.md", "\xff", 1), nil, readmeTime, port.RPCInvalidRequest, problem.ACSRequestInvalid, true},
		{"unmapped hook", strings.Replace(unsigned, `"steps/toolCallRequest"`, `"steps/sessionStart"`, 1), nil, readmeTime, rpcCapabilityNotNegotiated, problem.ACSMethodUnsupported, false},
		{"unsigned handshake while a secret is set", string(hello(t, []string{"0.1.0"})), katSecretConfig(), readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, false},
		{"unsigned while a secret is set", unsigned, katSecretConfig(), readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, true},
		{"signed while no secret is set", signed, nil, readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, true},
		{"unknown key_id", signed, other, readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, true},
		{"wrong signature", strings.Replace(signed, "/reports/q3-summary.md", "/reports/q4-summary.md", 1), katSecretConfig(), readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, true},
		{"signature not base64", strings.Replace(signed, "odebtunpVzqFPUybfY19dBrj5u63etOvJYlADI4YHfI=", "!!!", 1), katSecretConfig(), readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, true},
		{"unsupported algorithm", strings.Replace(signed, `"HMAC-SHA256"`, `"ECDSA-P256"`, 1), katSecretConfig(), readmeTime, rpcSignatureInvalid, problem.ACSSignatureInvalid, true},
		{"timestamp too old", unsigned, nil, readmeTime.Add(5*time.Minute + time.Second), rpcTimestampOutOfWindow, problem.ACSTimestampOutOfWindow, true},
		{"timestamp in the future", unsigned, nil, readmeTime.Add(-5*time.Minute - time.Second), rpcTimestampOutOfWindow, problem.ACSTimestampOutOfWindow, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := newAt(tc.now, allowGuard, tc.secret).Answer([]byte(tc.msg))
			if tc.deny {
				assertFailureDeny(t, reply.Body, tc.code)
				if reply.Failure != tc.code {
					t.Fatalf("Failure = %q, want %q", reply.Failure, tc.code)
				}
				assertSignedIff(t, reply.Body, tc.secret, sessionOf(t, tc.msg))
				return
			}
			data := assertError(t, reply, tc.rpc, tc.code)
			if tc.code == problem.ACSTimestampOutOfWindow && data["skew_window_ms"] != float64(300000) {
				t.Fatalf("data.skew_window_ms = %v, want 300000", data["skew_window_ms"])
			}
		})
	}
}

// TestAnswer_ReplayedRequestID_IsRefused answers a request once and
// refuses it the second time, signed or not.
func TestAnswer_ReplayedRequestID_IsRefused(t *testing.T) {
	cases := map[string]struct {
		msg    []byte
		secret *port.Secret
	}{
		"signed":   {readKAT(t, "readme-file-read.signed.json"), katSecretConfig()},
		"unsigned": {readExample(t, "readme-file-read.request.json"), nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v := newAt(readmeTime, allowGuard, tc.secret)
			if first := v.Answer(tc.msg); first.Failure != "" {
				t.Fatalf("first answer failed: %s", first.Body)
			}
			replay := v.Answer(tc.msg)
			assertFailureDeny(t, replay.Body, problem.ACSReplay)
			if replay.Failure != problem.ACSReplay {
				t.Fatalf("Failure = %q, want %q", replay.Failure, problem.ACSReplay)
			}
			assertSignedIff(t, replay.Body, tc.secret, sessionOf(t, string(tc.msg)))
		})
	}
}

// TestAnswer_UnsignedErrorWhenTheIDCannotBeRead answers a parse error with
// a null id, as JSON-RPC requires.
func TestAnswer_UnsignedErrorWhenTheIDCannotBeRead(t *testing.T) {
	m := response(t, newAt(readmeTime, allowGuard, nil).Answer([]byte(`{`)).Body)
	if m["id"] != nil {
		t.Fatalf("id = %v, want null", m["id"])
	}
}

// signWith signs raw (a request) the way an Observed Agent does, for tests
// that need a fresh signed request.
func signWith(t *testing.T, raw []byte, secret []byte, keyID string) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	p := env["params"].(map[string]any)
	canonical, err := canonicalize(raw, "params")
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveKey(secret, p["metadata"].(map[string]any)["session_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	p["signature"] = map[string]any{"algorithm": "HMAC-SHA256", "value": base64.StdEncoding.EncodeToString(mac(key, canonical)), "key_id": keyID}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAnswer_SignedHandshake_AdvertisesHMAC answers a verified handshake
// with HMAC-SHA256 among the algorithms and a signed ServerHello.
func TestAnswer_SignedHandshake_AdvertisesHMAC(t *testing.T) {
	raw := signWith(t, hello(t, []string{"0.1.0"}), katSecret, katKeyID)
	r := result(t, newAt(readmeTime, allowGuard, katSecretConfig()).Answer(raw).Body)
	if got, _ := json.Marshal(r["signature_algorithms_supported"]); string(got) != `["HMAC-SHA256"]` {
		t.Fatalf("signature_algorithms_supported = %s", got)
	}
	if _, ok := r["signature"].(map[string]any); !ok {
		t.Fatalf("ServerHello to a verified request is unsigned: %v", r)
	}
}

// TestAnswer_ForgetsRequestIDsPastTheSkewWindow keeps memory bounded: a
// request_id older than the timestamp window can no longer be replayed
// (its timestamp is refused first), so it is pruned.
func TestAnswer_ForgetsRequestIDsPastTheSkewWindow(t *testing.T) {
	now := readmeTime
	v := New(port.Config{Guard: allowGuard, Now: func() time.Time { return now }}).(*version)
	first := readExample(t, "readme-file-read.request.json")
	if r := v.Answer(first); r.Failure != "" {
		t.Fatalf("first answer failed: %s", r.Body)
	}
	now = readmeTime.Add(skewWindow + time.Minute)
	second := bytes.Replace(first, []byte("b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11"), []byte("c4f2d0a1-4c32-4c8b-8a3f-7b7e3f7b0b22"), 1)
	second = bytes.Replace(second, []byte(readmeTime.Format(time.RFC3339)), []byte(now.Format(time.RFC3339)), 1)
	if r := v.Answer(second); r.Failure != "" {
		t.Fatalf("second answer failed: %s", r.Body)
	}
	if n := v.remembered(); n != 1 {
		t.Fatalf("remembered request_ids = %d, want 1 (the first one pruned)", n)
	}
}

// remembered is how many request_ids veil holds to refuse replays.
func (v *version) remembered() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.seen) != len(v.forgets) {
		panic("replay map and forget queue disagree")
	}
	return len(v.seen)
}

// sessionOf is the metadata.session_id of a request.
func sessionOf(t *testing.T, msg string) string {
	t.Helper()
	var req struct {
		Params struct {
			Metadata struct {
				SessionID string `json:"session_id"`
			} `json:"metadata"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(msg), &req); err != nil {
		t.Fatal(err)
	}
	return req.Params.Metadata.SessionID
}

// assertSignedIff checks that a response carries a valid result.signature
// under secret's session key when veil holds a secret, and none otherwise:
// a host that requires signed responses treats an unsigned deny as a
// failure and applies on_decision_failure.
func assertSignedIff(t *testing.T, body []byte, secret *port.Secret, session string) {
	t.Helper()
	sig, signed := result(t, body)["signature"].(map[string]any)
	if secret == nil {
		if signed {
			t.Fatalf("result.signature = %v, want none without a secret", sig)
		}
		return
	}
	if !signed || sig["algorithm"] != "HMAC-SHA256" || sig["key_id"] != secret.KeyID {
		t.Fatalf("result.signature = %v, want HMAC-SHA256 with key_id %s", sig, secret.KeyID)
	}
	canonical, err := canonicalize(body, "result")
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveKey(secret.Bytes, session)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString(mac(key, canonical)); sig["value"] != want {
		t.Fatalf("result.signature.value = %v, want %s", sig["value"], want)
	}
}

// TestCheckReplay_CostDoesNotGrowWithRememberedIDs remembers many
// request_ids, none yet forgettable, then a few out-of-order ones expire.
// Each request must cost the ids it looks up or forgets, not every id
// remembered: a full scan per request makes this quadratic (minutes).
func TestCheckReplay_CostDoesNotGrowWithRememberedIDs(t *testing.T) {
	const n = 100000
	now := readmeTime
	v := New(port.Config{Guard: allowGuard, Now: func() time.Time { return now }}).(*version)
	at := func(id int, ts time.Time) envelope {
		var env envelope
		env.params.RequestID = fmt.Sprintf("id-%d", id)
		env.params.Timestamp = ts.Format(time.RFC3339Nano)
		env.params.Metadata.SessionID = fmt.Sprintf("s-%d", id%7)
		return env
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		// Timestamps not in arrival order: the oldest arrives last.
		if ref := v.checkReplay(at(i, readmeTime.Add(time.Duration(n-i)*time.Millisecond))); ref != nil {
			t.Fatalf("request %d refused: %+v", i, ref)
		}
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("%d requests took %v, want work independent of the ids remembered", n, elapsed)
	}
	if ref := v.checkReplay(at(0, readmeTime)); ref == nil || ref.code != problem.ACSReplay {
		t.Fatalf("replayed id-0 = %+v, want %s", ref, problem.ACSReplay)
	}
	// Forget exactly the ids whose timestamp + skewWindow is before now.
	now = readmeTime.Add(skewWindow + time.Duration(n/2)*time.Millisecond).Add(time.Millisecond / 2)
	if ref := v.checkReplay(at(n, now)); ref != nil {
		t.Fatalf("fresh request refused: %+v", ref)
	}
	if got, want := v.remembered(), n/2+1; got != want {
		t.Fatalf("remembered = %d, want %d", got, want)
	}
	if ref := v.checkReplay(at(n-1, readmeTime.Add(time.Millisecond))); ref != nil {
		t.Fatalf("forgotten id-%d refused: %+v", n-1, ref)
	}
}
