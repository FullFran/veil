package port

import (
	"bytes"
	"encoding/json"

	"github.com/FullFran/veil/internal/problem"
)

// JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification#error_object)
// and the ones ACS reserves in -32000..-32099 that veil raises.
const (
	RPCParseError     = -32700
	RPCInvalidRequest = -32600
	RPCInvalidParams  = -32602
	RPCInternalError  = -32603
)

// errorObject is a JSON-RPC 2.0 error. Data carries the RFC 9457 problem
// as data.problem, with its code and title mirrored in data.reason and
// data.message, the two members ACS asks error data to have.
type errorObject struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

type errorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   errorObject     `json:"error"`
}

// ErrorReply answers a message with a JSON-RPC error of rpcCode carrying
// the problem for code, plus extra data members (for example
// supported_versions). id is echoed when it is a JSON string or number;
// anything else (missing, null, an object) is answered with a null id, as
// JSON-RPC requires when the id cannot be determined.
func ErrorReply(id json.RawMessage, rpcCode int, code problem.Code, extra map[string]any) Reply {
	p := problem.New(code)
	data := map[string]any{"reason": string(code), "message": p.Title, "problem": p}
	for k, v := range extra {
		data[k] = v
	}
	body, err := json.Marshal(errorResponse{
		JSONRPC: "2.0",
		ID:      EchoID(id),
		Error:   errorObject{Code: rpcCode, Message: p.Title, Data: data},
	})
	if err != nil {
		// Every member above is a plain string, number or map of them.
		panic("port: marshal JSON-RPC error: " + err.Error())
	}
	return Reply{Body: body, Failure: code}
}

// EchoID returns id when it is a JSON string or number, and null otherwise.
func EchoID(id json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 {
		return json.RawMessage("null")
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return json.RawMessage("null")
	}
	switch v.(type) {
	case string, json.Number:
		return trimmed
	default:
		return json.RawMessage("null")
	}
}
