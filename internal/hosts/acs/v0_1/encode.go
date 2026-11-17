package v0_1

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/problem"
)

// Fixed reasoning texts: ACS requires reasoning on deny and modify, and a
// domain reason may be empty.
const (
	reasonDenied    = "veil policy denied this step"
	reasonRewritten = "veil replaced sensitive values with session pseudonyms"
)

// newResult is the AcsResult skeleton every decision shares.
func newResult(env envelope, decision string) map[string]any {
	return map[string]any{
		"type":        "final",
		"acs_version": Version,
		"request_id":  env.params.RequestID,
		"decision":    decision,
		"metadata":    map[string]any{"evaluator": "deterministic"},
	}
}

// failureDeny is the decision veil answers a valid hook with when it
// cannot decide: deny, never allow, ask or defer. ACS 6.4 makes the
// Observed Agent apply on_decision_failure (default proceed) to an error,
// but always honour a decision, so a failure is a deny that carries the
// problem in reason_codes and policy_data.veil.problem.
func failureDeny(env envelope, code problem.Code) map[string]any {
	p := problem.New(code)
	r := newResult(env, "deny")
	r["reasoning"] = p.Title
	r["reason_codes"] = []string{string(code)}
	r["policy_data"] = map[string]any{"veil": map[string]any{"problem": p}}
	return r
}

// encodeDecision maps a domain decision to an AcsResult. Allow, Deny and
// Rewrite map to allow, deny and modify; anything else is an error the
// caller turns into a failure deny. veil never emits ask or defer: it has
// no channel to a human approver (HCS-0005-R014, R015).
func encodeDecision(env envelope, h hook, d domain.Decision, evidence json.RawMessage) (map[string]any, error) {
	var r map[string]any
	switch d.Kind {
	case domain.Allow:
		r = newResult(env, "allow")
	case domain.Deny:
		r = newResult(env, "deny")
		r["reasoning"] = d.Reason
		if d.Reason == "" {
			r["reasoning"] = reasonDenied
		}
	case domain.Rewrite:
		mods, err := modifications(env, h, d)
		if err != nil {
			return nil, err
		}
		r = newResult(env, "modify")
		r["reasoning"] = reasonRewritten
		r["modifications"] = mods
	default:
		return nil, fmt.Errorf("acs v0.1: no ACS decision for %s", d.Kind)
	}
	if len(evidence) > 0 {
		r["policy_data"] = map[string]any{"veil": map[string]any{"evidence": evidence}}
	}
	return r, nil
}

// errUnredactable is a rewrite ACS cannot carry to everything the agent
// acts on: veil denies the step instead (problem.ACSUnredactable).
var errUnredactable = errors.New("acs v0.1: rewrite reaches data no modification can redact")

// unredactable are the payload members a modification cannot be trusted
// to reach: the tool name selects what runs, and raw_command is the
// shell-style form of the call, which a host may execute instead of the
// structured arguments.
var unredactable = map[string]bool{"/tool/name": true, "/raw_command": true}

// modifications expresses a rewrite in the structured ACS form. Each
// changed field is a pointer under params (see decodeHook):
//   - under /payload/arguments/<name>/value of steps/toolCallRequest, it
//     is parameter_overrides of that argument, its whole value rebuilt;
//   - anywhere else in the payload, it is a redaction whose JSON pointer
//     addresses the changed leaf in the payload;
//   - a member name, anything outside the payload (metadata, extra params
//     members), the tool name, raw_command, or an argument both overridden
//     and redacted is errUnredactable.
//
// A rewrite that changes nothing is an error, never a silent allow.
func modifications(env envelope, h hook, d domain.Decision) (map[string]any, error) {
	if d.Kind != domain.Rewrite {
		return nil, fmt.Errorf("acs v0.1: no rewrite for %s", d.Kind)
	}
	overrides := map[string]any{}
	var redactions []map[string]any
	for _, name := range slices.Sorted(maps.Keys(d.RedactedFields)) {
		replacement := d.RedactedFields[name]
		original, known := h.event.Fields[name]
		if known && original == replacement {
			continue
		}
		rel, inPayload := strings.CutPrefix(name, "/payload/")
		if !known || !inPayload || unredactable["/"+rel] {
			return nil, errUnredactable
		}
		rel = "/" + rel
		if arg, sub, ok := argumentValue(env.method, rel); ok {
			current, seen := overrides[arg]
			if !seen {
				current = h.args[arg]
			}
			rebuilt, ok := setLeaf(current, sub, replacement)
			if !ok {
				return nil, errUnredactable
			}
			overrides[arg] = rebuilt
			continue
		}
		redactions = append(redactions, map[string]any{"path": rel, "replacement": replacement})
	}
	for _, r := range redactions {
		for arg := range overrides {
			if p := r["path"].(string); strings.HasPrefix(p, "/arguments/"+escapePointer(arg)+"/") {
				return nil, errUnredactable
			}
		}
	}
	mods := map[string]any{}
	if len(overrides) > 0 {
		mods["parameter_overrides"] = overrides
	}
	if len(redactions) > 0 {
		mods["redactions"] = redactions
	}
	if len(mods) == 0 {
		return nil, errors.New("acs v0.1: rewrite changes nothing")
	}
	return mods, nil
}

// argumentValue splits a payload pointer of steps/toolCallRequest under
// /arguments/<name>/value into the argument name and the tokens below
// its value.
func argumentValue(method, pointer string) (string, []string, bool) {
	if method != methodToolRequest {
		return "", nil, false
	}
	tokens := strings.Split(pointer, "/")[1:]
	if len(tokens) < 3 || tokens[0] != "arguments" || tokens[2] != "value" {
		return "", nil, false
	}
	return unescapePointer(tokens[1]), tokens[3:], true
}

// setLeaf returns a copy of v with the leaf at the pointer tokens set to
// s, leaving v itself unchanged.
func setLeaf(v any, tokens []string, s string) (any, bool) {
	if len(tokens) == 0 {
		return s, true
	}
	switch t := v.(type) {
	case map[string]any:
		key := unescapePointer(tokens[0])
		child, ok := t[key]
		if !ok {
			return nil, false
		}
		rebuilt, ok := setLeaf(child, tokens[1:], s)
		if !ok {
			return nil, false
		}
		out := maps.Clone(t)
		out[key] = rebuilt
		return out, true
	case []any:
		i, err := strconv.Atoi(tokens[0])
		if err != nil || i < 0 || i >= len(t) {
			return nil, false
		}
		rebuilt, ok := setLeaf(t[i], tokens[1:], s)
		if !ok {
			return nil, false
		}
		out := slices.Clone(t)
		out[i] = rebuilt
		return out, true
	}
	return nil, false
}

func escapePointer(token string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(token)
}

func unescapePointer(token string) string {
	return strings.NewReplacer("~1", "/", "~0", "~").Replace(token)
}
