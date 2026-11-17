package v0_1

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// The ACS methods veil answers.
const (
	methodAgentTrigger    = "steps/agentTrigger"
	methodUserMessage     = "steps/userMessage"
	methodKnowledge       = "steps/knowledgeRetrieval"
	methodMemoryRetrieval = "steps/memoryContextRetrieval"
	methodToolRequest     = "steps/toolCallRequest"
	methodToolResult      = "steps/toolCallResult"
	methodHello           = "handshake/hello"
	methodPing            = "system/ping"
)

// payloadSchemas is the pinned schema of every method veil answers. The
// acs-provenance variants of the hook schemas only make provenance
// required, so the base schema accepts every payload they accept.
var payloadSchemas = map[string]string{
	methodAgentTrigger:    schemaAgentTrigger,
	methodUserMessage:     schemaUserMessage,
	methodKnowledge:       schemaKnowledge,
	methodMemoryRetrieval: schemaMemoryRetrieval,
	methodToolRequest:     schemaToolRequest,
	methodToolResult:      schemaToolResult,
	methodPing:            schemaPing,
	methodHello:           schemaClientHello,
}

// refusal is a request veil does not evaluate: the JSON-RPC code, veil's
// problem code and any extra error data members ACS defines for that
// code. On an evaluated hook the refusal is answered with a deny decision
// where one can be formed (see version.refuse); final keeps it a JSON-RPC
// error, for a request whose id or method cannot be read unambiguously.
type refusal struct {
	rpc   int
	code  problem.Code
	extra map[string]any
	final bool
}

func refuse(rpc int, code problem.Code) *refusal { return &refusal{rpc: rpc, code: code} }

type signature struct {
	Algorithm string
	Value     string
	KeyID     string
}

// params is what veil reads itself from a request's params.
type params struct {
	ACSVersion string
	RequestID  string
	Timestamp  string
	Metadata   struct {
		SessionID string
	}
	Signature *signature
}

// envelope is a request read by the strict parser: its raw bytes (what
// the signature covers), its id, method and params, the params tree with
// exact member names, and its payload for per-method validation.
type envelope struct {
	raw     []byte
	id      json.RawMessage
	method  string
	params  params
	tree    map[string]any
	payload any
}

// decodeEnvelope parses one JSON-RPC message and validates it against the
// vendored request envelope schema. Unparseable JSON is -32700; a batch,
// a response or anything off the schema is -32600. So is a message two
// parsers could read differently (a repeated member name, one that
// differs from another only by case, a string with invalid UTF-8 or a
// lone surrogate): the schema, the signature and the host must all see
// the one document veil evaluates. When that ambiguity is outside params'
// payload, metadata and signature, the id or method cannot be trusted and
// the refusal stays a JSON-RPC error with no id.
func decodeEnvelope(raw []byte) (envelope, *refusal) {
	doc, ambiguities, err := parseJSON(raw)
	if err != nil {
		return envelope{}, refuse(port.RPCParseError, problem.InputInvalid)
	}
	env := envelope{raw: raw}
	obj, ok := doc.(map[string]any)
	if !ok {
		return env, refuse(port.RPCInvalidRequest, problem.ACSRequestInvalid)
	}
	for _, a := range ambiguities {
		if !insideParamsContent(a.pointer) {
			return env, &refusal{rpc: port.RPCInvalidRequest, code: problem.ACSRequestInvalid, final: true}
		}
	}
	if id, ok := obj["id"]; ok {
		env.id, _ = json.Marshal(id)
	}
	env.method, _ = obj["method"].(string)
	env.tree, _ = obj["params"].(map[string]any)
	env.params = readParams(env.tree)
	env.payload = env.tree["payload"]
	if len(ambiguities) > 0 {
		return env, refuse(port.RPCInvalidRequest, problem.ACSRequestInvalid)
	}
	if err := validate(schemaRequest, doc); err != nil {
		return env, refuse(port.RPCInvalidRequest, problem.ACSRequestInvalid)
	}
	return env, nil
}

// insideParamsContent reports whether pointer is in params' payload,
// metadata or signature, none of which a deny decision echoes.
func insideParamsContent(pointer string) bool {
	for _, member := range []string{"/params/payload", "/params/metadata", "/params/signature"} {
		if pointer == member || strings.HasPrefix(pointer, member+"/") {
			return true
		}
	}
	return false
}

// readParams reads the members of params veil uses. Anything of the
// wrong type reads as empty: the envelope schema refuses it.
func readParams(p map[string]any) params {
	str := func(m map[string]any, k string) string {
		s, _ := m[k].(string)
		return s
	}
	out := params{ACSVersion: str(p, "acs_version"), RequestID: str(p, "request_id"), Timestamp: str(p, "timestamp")}
	if m, ok := p["metadata"].(map[string]any); ok {
		out.Metadata.SessionID = str(m, "session_id")
	}
	if _, present := p["signature"]; present {
		sig, _ := p["signature"].(map[string]any)
		out.Signature = &signature{Algorithm: str(sig, "algorithm"), Value: str(sig, "value"), KeyID: str(sig, "key_id")}
	}
	return out
}

// validatePayload checks the payload against the schema of its method.
// Methods veil does not answer have no schema here; dispatch refuses them.
func validatePayload(env envelope) *refusal {
	loc, ok := payloadSchemas[env.method]
	if !ok {
		return nil
	}
	if err := validate(loc, env.payload); err != nil {
		return refuse(port.RPCInvalidParams, problem.ACSRequestInvalid)
	}
	return nil
}

// validateRequest is decodeEnvelope plus validatePayload: a whole request
// against the vendored schemas.
func validateRequest(raw []byte) *refusal {
	env, ref := decodeEnvelope(raw)
	if ref != nil {
		return ref
	}
	return validatePayload(env)
}

// hook is a decoded hook request: the host-neutral event veil evaluates
// and, for steps/toolCallRequest, its arguments by name (the unwrapped
// values a rewrite overrides).
type hook struct {
	event domain.Event
	args  map[string]any
}

// structural are the params members veil reads itself and never scans:
// they are protocol values, not content, and the answer must echo or
// verify them as they are.
var structural = map[string]bool{
	"/acs_version": true, "/request_id": true, "/timestamp": true,
	"/signature": true, "/metadata/session_id": true,
}

// decodeHook maps a validated hook request to a domain event. Text that
// enters the model's context from outside it is a prompt: steps/userMessage
// and steps/agentTrigger are EventPromptSubmit. Text a tool or store hands
// back to the model is tool output: steps/toolCallResult,
// steps/knowledgeRetrieval and steps/memoryContextRetrieval are
// EventToolOutput. steps/toolCallRequest is EventToolArgs, with Args the
// unwrapped argument values. Any other method is not a hook veil maps.
//
// Whatever the hook, the fields are every leaf of params (by its RFC 6901
// pointer under params) and every member name (by "key " and the pointer
// of its member), except the structural members: detectors see each piece
// of text the request carries, not a list of fields someone chose.
func decodeHook(env envelope) (hook, *refusal) {
	e := domain.Event{Host: domain.HostACS, SessionID: env.params.Metadata.SessionID}
	payload, _ := env.payload.(map[string]any)
	h := hook{}
	switch env.method {
	case methodUserMessage, methodAgentTrigger:
		e.Kind = domain.EventPromptSubmit
	case methodKnowledge, methodMemoryRetrieval:
		e.Kind = domain.EventToolOutput
		e.ToolName = strings.TrimPrefix(env.method, "steps/")
	case methodToolResult:
		e.Kind = domain.EventToolOutput
		e.ToolName = toolName(payload)
	case methodToolRequest:
		e.Kind = domain.EventToolArgs
		e.ToolName = toolName(payload)
		arguments, _ := payload["arguments"].(map[string]any)
		h.args = make(map[string]any, len(arguments))
		for name, arg := range arguments {
			if a, ok := arg.(map[string]any); ok {
				h.args[name] = a["value"]
			}
		}
		e.Args = h.args
	default:
		return hook{}, refuse(rpcCapabilityNotNegotiated, problem.ACSMethodUnsupported)
	}
	e.Fields = map[string]string{}
	scan(env.tree, "", e.Fields)
	e.Text = fieldText(e.Fields)
	h.event = e
	return h, nil
}

func toolName(payload map[string]any) string {
	tool, _ := payload["tool"].(map[string]any)
	name, _ := tool["name"].(string)
	return name
}

// scan adds to fields every leaf and member name under v, at pointer.
func scan(v any, pointer string, fields map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := pointer + "/" + escapePointer(k)
			fields["key "+p] = k
			if !structural[p] {
				scan(child, p, fields)
			}
		}
	case []any:
		for i, child := range t {
			scan(child, pointer+"/"+strconv.Itoa(i), fields)
		}
	case string:
		fields[pointer] = t
	case json.Number:
		fields[pointer] = t.String()
	case bool:
		fields[pointer] = strconv.FormatBool(t)
	}
}

// fieldText is one "name: value" line per field, sorted by name, for
// detectors that scan free text.
func fieldText(fields map[string]string) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(fields[name])
		b.WriteString("\n")
	}
	return b.String()
}

// ACS error codes (Specification section 17.1) veil raises.
const (
	rpcSessionRefused          = -32000
	rpcUnsupportedVersion      = -32001
	rpcCapabilityNotNegotiated = -32003
	rpcSignatureInvalid        = -32004
	rpcReplayDetected          = -32005
	rpcTimestampOutOfWindow    = -32006
)
