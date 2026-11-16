package v0_1

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// Version is the ACS wire version this package speaks.
const Version = "0.1.0"

// skewWindow is the timestamp tolerance veil applies and advertises: the
// RECOMMENDED default of ServerHello.skew_window_ms (Specification 10.3).
const skewWindow = 5 * time.Minute

// defaultTimeoutMS is the per-decision timeout veil advertises.
const defaultTimeoutMS = 10000

// evaluated is every hook veil maps to a domain event, in the order
// ServerHello lists them: each hook whose payload carries text that enters
// the model's context, plus the tool call itself. The README lists the
// hooks left out and why.
var evaluated = []string{
	methodAgentTrigger, methodUserMessage, methodKnowledge, methodMemoryRetrieval,
	methodToolRequest, methodToolResult,
}

type version struct {
	cfg  port.Config
	mu   sync.Mutex
	seen map[string]map[string]time.Time // session_id -> request_id -> when it can be forgotten
}

// New returns the ACS 0.1.0 answerer for cfg. It remembers request_ids
// per session to refuse replays, each until its timestamp leaves the skew
// window: from then on checkTimestamp refuses the request anyway.
func New(cfg port.Config) port.Version {
	return &version{cfg: cfg, seen: map[string]map[string]time.Time{}}
}

// Answer answers one JSON-RPC message. The checks run in this order, each
// failing closed: envelope schema, version, payload schema, method, then
// (except for system/ping) evaluability, signature, timestamp and replay.
func (v *version) Answer(msg []byte) port.Reply {
	env, ref := decodeEnvelope(msg)
	if ref == nil && env.params.ACSVersion != Version {
		ref = &refusal{rpc: rpcUnsupportedVersion, code: problem.ACSVersionUnsupported,
			extra: map[string]any{"supported_versions": []string{Version}}}
	}
	if ref == nil {
		ref = validatePayload(env)
	}
	if ref != nil {
		return v.refuse(env, ref)
	}

	switch {
	case env.method == methodPing:
		return v.ping(env)
	case env.method == methodHello, slices.Contains(evaluated, env.method):
	default:
		return v.refuse(env, refuse(rpcCapabilityNotNegotiated, problem.ACSMethodUnsupported))
	}

	if v.cfg.Unavailable != "" {
		if env.method == methodHello {
			return v.refuse(env, refuse(rpcSessionRefused, v.cfg.Unavailable))
		}
		return v.reply(env, failureDeny(env, v.cfg.Unavailable), false, v.cfg.Unavailable)
	}

	verified, ref := v.verify(env)
	if ref == nil {
		ref = v.checkTimestamp(env)
	}
	if ref == nil {
		ref = v.checkReplay(env)
	}
	if ref != nil {
		return v.refuse(env, ref)
	}

	if env.method == methodHello {
		return v.hello(env, verified)
	}
	h, ref := decodeHook(env)
	if ref != nil {
		return v.refuse(env, ref)
	}
	decision, evidence, code := v.cfg.Guard(h.event)
	if code != "" {
		return v.reply(env, failureDeny(env, code), verified, code)
	}
	r, err := encodeDecision(env, h, decision, evidence)
	if errors.Is(err, errUnredactable) {
		return v.reply(env, failureDeny(env, problem.ACSUnredactable), verified, problem.ACSUnredactable)
	}
	if err != nil {
		return v.reply(env, failureDeny(env, problem.Internal), verified, problem.Internal)
	}
	return v.reply(env, r, verified, "")
}

// deniable are the refusals of an evaluated hook veil answers with a deny
// decision instead of an error: ACS handshake.json makes the Observed
// Agent apply on_decision_failure (default proceed) to an error, and veil
// keeps no handshake state to know the host chose deny.
var deniable = map[int]bool{
	port.RPCInvalidRequest:  true,
	port.RPCInvalidParams:   true,
	rpcSignatureInvalid:     true,
	rpcReplayDetected:       true,
	rpcTimestampOutOfWindow: true,
}

// refuse answers a refusal. On an evaluated hook it is an unsigned deny
// carrying the problem, when that deny is a valid ACS response (it needs
// a string or number id and a uuid request_id); otherwise, and for every
// other method, it is the JSON-RPC error.
func (v *version) refuse(env envelope, r *refusal) port.Reply {
	if !r.final && deniable[r.rpc] && slices.Contains(evaluated, env.method) {
		reply := v.reply(env, failureDeny(env, r.code), false, r.code)
		if validateResponse(reply.Body) == nil {
			return reply
		}
	}
	return port.ErrorReply(env.id, r.rpc, r.code, r.extra)
}

// verify checks the request signature against the configured secret.
// Without a secret, only unsigned requests pass (a key_id then names no
// key veil has); with one, the signature is mandatory. It reports whether
// the request was verified, so the response is signed back.
func (v *version) verify(env envelope) (bool, *refusal) {
	invalid := refuse(rpcSignatureInvalid, problem.ACSSignatureInvalid)
	sig, secret := env.params.Signature, v.cfg.Secret
	if secret == nil {
		if sig != nil {
			return false, invalid
		}
		return false, nil
	}
	if sig == nil || sig.Algorithm != signatureAlgorithm || sig.KeyID != secret.KeyID {
		return false, invalid
	}
	got, err := base64.StdEncoding.Strict().DecodeString(sig.Value)
	if err != nil {
		return false, invalid
	}
	canonical, err := canonicalize(env.raw, "params")
	if err != nil {
		return false, invalid
	}
	key, err := deriveKey(secret.Bytes, env.params.Metadata.SessionID)
	if err != nil {
		return false, invalid
	}
	if !hmac.Equal(got, mac(key, canonical)) {
		return false, invalid
	}
	return true, nil
}

func (v *version) checkTimestamp(env envelope) *refusal {
	ts, err := time.Parse(time.RFC3339Nano, env.params.Timestamp)
	if err != nil {
		return refuse(port.RPCInvalidRequest, problem.ACSRequestInvalid)
	}
	skew := v.cfg.Clock().Sub(ts)
	if skew > skewWindow || skew < -skewWindow {
		return &refusal{rpc: rpcTimestampOutOfWindow, code: problem.ACSTimestampOutOfWindow,
			extra: map[string]any{"skew_window_ms": skewWindow.Milliseconds()}}
	}
	return nil
}

func (v *version) checkReplay(env envelope) *refusal {
	ts, err := time.Parse(time.RFC3339Nano, env.params.Timestamp)
	if err != nil {
		return refuse(port.RPCInvalidRequest, problem.ACSRequestInvalid)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.cfg.Clock()
	for session, ids := range v.seen {
		for id, forget := range ids {
			if now.After(forget) {
				delete(ids, id)
			}
		}
		if len(ids) == 0 {
			delete(v.seen, session)
		}
	}
	session := env.params.Metadata.SessionID
	ids := v.seen[session]
	if ids == nil {
		ids = map[string]time.Time{}
		v.seen[session] = ids
	}
	if _, dup := ids[env.params.RequestID]; dup {
		return refuse(rpcReplayDetected, problem.ACSReplay)
	}
	ids[env.params.RequestID] = ts.Add(skewWindow)
	return nil
}

func (v *version) ping(env envelope) port.Reply {
	payload := map[string]any{"status": "ok", "server_timestamp": v.cfg.Clock().UTC().Format(time.RFC3339Nano)}
	if p, ok := env.payload.(map[string]any); ok {
		if echo, ok := p["echo"].(string); ok {
			payload["echo"] = echo
		}
	}
	r := newResult(env, "allow")
	r["payload"] = payload
	return v.reply(env, r, false, "")
}

func (v *version) hello(env envelope, verified bool) port.Reply {
	payload, _ := env.payload.(map[string]any)
	strs := func(member string) []string {
		items, _ := payload[member].([]any)
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	versions, implemented := strs("acs_versions_supported"), strs("methods_implemented")
	if !slices.Contains(versions, Version) {
		return v.refuse(env, &refusal{rpc: rpcUnsupportedVersion, code: problem.ACSVersionUnsupported,
			extra: map[string]any{"supported_versions": []string{Version}}})
	}
	methods := []string{}
	for _, m := range evaluated {
		if slices.Contains(implemented, m) {
			methods = append(methods, m)
		}
	}
	algorithms := []string{}
	if v.cfg.Secret != nil {
		algorithms = append(algorithms, signatureAlgorithm)
	}
	return v.reply(env, map[string]any{
		"negotiated_version":             Version,
		"methods_evaluated":              methods,
		"selected_transport":             "stdio",
		"signature_algorithms_supported": algorithms,
		"timeout_config":                 map[string]any{"default_ms": defaultTimeoutMS},
		"skew_window_ms":                 skewWindow.Milliseconds(),
		"on_decision_failure":            "deny",
		"policy_requires_provenance":     false,
	}, verified, "")
}

// reply wraps result in a JSON-RPC response and, when the request was
// verified, signs it with the request's session key over the JCS form of
// the whole response minus result.signature (Specification section 10).
func (v *version) reply(env envelope, result map[string]any, verified bool, failure problem.Code) port.Reply {
	resp := map[string]any{"jsonrpc": "2.0", "id": port.EchoID(env.id), "result": result}
	body, err := json.Marshal(resp)
	if err == nil && verified {
		var canonical, key []byte
		canonical, err = canonicalize(body, "result")
		if err == nil {
			key, err = deriveKey(v.cfg.Secret.Bytes, env.params.Metadata.SessionID)
		}
		if err == nil {
			result["signature"] = map[string]any{
				"algorithm": signatureAlgorithm,
				"value":     signatureValue(key, canonical),
				"key_id":    v.cfg.Secret.KeyID,
			}
			body, err = json.Marshal(resp)
		}
	}
	if err != nil {
		return port.ErrorReply(env.id, port.RPCInternalError, problem.Internal, nil)
	}
	return port.Reply{Body: body, Failure: failure}
}
