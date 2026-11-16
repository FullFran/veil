package v0_1

import (
	"bytes"
	"encoding/json"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The ACS methods veil answers.
const (
	methodToolRequest = "steps/toolCallRequest"
	methodToolResult  = "steps/toolCallResult"
	methodHello       = "handshake/hello"
	methodPing        = "system/ping"
)

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
	var loc string
	switch env.method {
	case methodToolRequest:
		loc = schemaToolRequest
	case methodToolResult:
		loc = schemaToolResult
	case methodPing:
		loc = schemaPing
	case methodHello:
		loc = schemaClientHello
	default:
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
	event   domain.Event
	args    map[string]any // steps/toolCallRequest: argument name to value
	outputs map[string]any // steps/toolCallResult: {"outputs": [value, ...]}
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
	Outputs []struct {
		Value any `json:"value"`
	} `json:"outputs"`
}

// decodeHook maps a validated hook request to a domain event:
// steps/toolCallRequest to EventToolArgs over the unwrapped argument
// values, steps/toolCallResult to EventToolOutput over the output values
// keyed outputs.<index>. Any other method is not a hook veil maps.
func decodeHook(env envelope) (hook, *refusal) {
	base := domain.Event{Host: domain.HostACS, SessionID: env.params.Metadata.SessionID}
	switch env.method {
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
		values := make([]any, len(p.Outputs))
		for i, o := range p.Outputs {
			values[i] = o.Value
		}
		outputs := map[string]any{"outputs": values}
		fields, text := domain.FlattenArgs(outputs)
		base.Kind = domain.EventToolOutput
		base.ToolName = p.Tool.Name
		base.Fields, base.Text = fields, text
		return hook{event: base, outputs: outputs}, nil
	default:
		return hook{}, refuse(rpcCapabilityNotNegotiated, problem.ACSMethodUnsupported)
	}
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
