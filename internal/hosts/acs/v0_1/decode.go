package v0_1

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
	"github.com/santhosh-tekuri/jsonschema/v6"
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

// refusal is a request veil answers with a JSON-RPC error instead of a
// decision: the JSON-RPC code, veil's problem code and any extra error
// data members ACS defines for that code.
type refusal struct {
	rpc   int
	code  problem.Code
	extra map[string]any
}

func refuse(rpc int, code problem.Code) *refusal { return &refusal{rpc: rpc, code: code} }

type signature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	KeyID     string `json:"key_id"`
}

type params struct {
	ACSVersion string `json:"acs_version"`
	RequestID  string `json:"request_id"`
	Timestamp  string `json:"timestamp"`
	Metadata   struct {
		SessionID string `json:"session_id"`
	} `json:"metadata"`
	Payload   json.RawMessage `json:"payload"`
	Signature *signature      `json:"signature"`
}

// envelope is a request that validated against the request envelope
// schema: its raw bytes (what the signature covers), its id, method and
// params, and the schema-library view of its payload for per-method
// validation.
type envelope struct {
	raw     []byte
	id      json.RawMessage
	method  string
	params  params
	payload any
}

// decodeEnvelope parses one JSON-RPC message and validates it against the
// vendored request envelope schema. Unparseable JSON is -32700; a batch,
// a response or anything off the schema is -32600.
func decodeEnvelope(raw []byte) (envelope, *refusal) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return envelope{}, refuse(port.RPCParseError, problem.InputInvalid)
	}
	var head struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params params          `json:"params"`
	}
	obj, isObject := doc.(map[string]any)
	if isObject {
		// Best effort: only to echo the id and read typed fields; the
		// schema below is what decides whether the message is valid.
		_ = json.Unmarshal(raw, &head)
	}
	env := envelope{raw: raw, id: head.ID}
	if err := validate(schemaRequest, doc); err != nil {
		return env, refuse(port.RPCInvalidRequest, problem.ACSRequestInvalid)
	}
	env.method = head.Method
	env.params = head.Params
	env.payload = obj["params"].(map[string]any)["payload"]
	return env, nil
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
// and what the encoder needs to express a rewrite in ACS terms.
type hook struct {
	event domain.Event
	// args is steps/toolCallRequest's arguments, name to value; a rewrite
	// of them is parameter_overrides.
	args map[string]any
	// doc is, for every other hook, the payload members veil evaluates,
	// with the values of the wrapped members unwrapped; a rewrite of them
	// is redactions into the payload.
	doc map[string]any
	// wrapped names the members of doc that are arrays of {"value": v}
	// items in the payload, so /<member>/<i>/value addresses item i.
	wrapped map[string]bool
}

// valueItems is an array of payload items that carry their text in value.
type valueItems []struct {
	Value any `json:"value"`
}

func (items valueItems) values() []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = item.Value
	}
	return out
}

type userMessagePayload struct {
	Content valueItems `json:"content"`
}

type agentTriggerPayload struct {
	TriggerSource any `json:"trigger_source"`
	Intent        *struct {
		Raw *string `json:"raw"`
	} `json:"intent"`
}

type retrievalPayload struct {
	Results valueItems `json:"results"`
}

type toolRequestPayload struct {
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	Arguments map[string]struct {
		Value any `json:"value"`
	} `json:"arguments"`
}

type toolResultPayload struct {
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	Outputs valueItems `json:"outputs"`
}

// decodeHook maps a validated hook request to a domain event. Text that
// enters the model's context from outside it is a prompt:
// steps/userMessage (the content values, keyed content.<i>) and
// steps/agentTrigger (trigger_source and intent.raw) are
// EventPromptSubmit. Text a tool or store hands back to the model is tool
// output: steps/toolCallResult (outputs.<i>), steps/knowledgeRetrieval and
// steps/memoryContextRetrieval (results.<i>) are EventToolOutput.
// steps/toolCallRequest is EventToolArgs over the unwrapped argument
// values. Any other method is not a hook veil maps.
func decodeHook(env envelope) (hook, *refusal) {
	base := domain.Event{Host: domain.HostACS, SessionID: env.params.Metadata.SessionID}
	invalid := refuse(port.RPCInvalidParams, problem.ACSRequestInvalid)
	switch env.method {
	case methodUserMessage:
		var p userMessagePayload
		if err := domain.DecodeJSON(env.params.Payload, &p); err != nil {
			return hook{}, invalid
		}
		doc := map[string]any{"content": p.Content.values()}
		return docHook(base, domain.EventPromptSubmit, doc, "content"), nil
	case methodAgentTrigger:
		var p agentTriggerPayload
		if err := domain.DecodeJSON(env.params.Payload, &p); err != nil {
			return hook{}, invalid
		}
		doc := map[string]any{}
		if p.TriggerSource != nil {
			doc["trigger_source"] = p.TriggerSource
		}
		if p.Intent != nil && p.Intent.Raw != nil {
			doc["intent"] = map[string]any{"raw": *p.Intent.Raw}
		}
		return docHook(base, domain.EventPromptSubmit, doc), nil
	case methodKnowledge, methodMemoryRetrieval:
		var p retrievalPayload
		if err := domain.DecodeJSON(env.params.Payload, &p); err != nil {
			return hook{}, invalid
		}
		base.ToolName = strings.TrimPrefix(env.method, "steps/")
		doc := map[string]any{"results": p.Results.values()}
		return docHook(base, domain.EventToolOutput, doc, "results"), nil
	case methodToolRequest:
		var p toolRequestPayload
		if err := domain.DecodeJSON(env.params.Payload, &p); err != nil {
			return hook{}, refuse(port.RPCInvalidParams, problem.ACSRequestInvalid)
		}
		args := make(map[string]any, len(p.Arguments))
		for name, arg := range p.Arguments {
			args[name] = arg.Value
		}
		fields, text := domain.FlattenArgs(args)
		base.Kind = domain.EventToolArgs
		base.ToolName = p.Tool.Name
		base.Fields, base.Text, base.Args = fields, text, args
		return hook{event: base, args: args}, nil
	case methodToolResult:
		var p toolResultPayload
		if err := domain.DecodeJSON(env.params.Payload, &p); err != nil {
			return hook{}, refuse(port.RPCInvalidParams, problem.ACSRequestInvalid)
		}
		base.ToolName = p.Tool.Name
		doc := map[string]any{"outputs": p.Outputs.values()}
		return docHook(base, domain.EventToolOutput, doc, "outputs"), nil
	default:
		return hook{}, refuse(rpcCapabilityNotNegotiated, problem.ACSMethodUnsupported)
	}
}

// docHook is a hook of kind over doc, whose wrapped members are arrays of
// {"value": v} items in the payload.
func docHook(base domain.Event, kind domain.EventKind, doc map[string]any, wrapped ...string) hook {
	fields, text := domain.FlattenArgs(doc)
	base.Kind = kind
	base.Fields, base.Text = fields, text
	h := hook{event: base, doc: doc, wrapped: map[string]bool{}}
	for _, member := range wrapped {
		h.wrapped[member] = true
	}
	return h
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
