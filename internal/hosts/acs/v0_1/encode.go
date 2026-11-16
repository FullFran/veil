package v0_1

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
		mods, err := modifications(h, d)
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

// modifications expresses a rewrite in the structured ACS form: for tool
// arguments, parameter_overrides of each top-level argument that changed;
// for tool output, redactions whose JSON pointers address the changed
// leaves under /outputs/<i>/value. A rewrite that changes nothing is an
// error, never a silent allow.
func modifications(h hook, d domain.Decision) (map[string]any, error) {
	switch h.event.Kind {
	case domain.EventToolArgs:
		rebuilt := domain.RebuildArgs(h.args, d.RedactedFields)
		overrides := map[string]any{}
		for name, value := range rebuilt {
			if !reflect.DeepEqual(value, h.args[name]) {
				overrides[name] = value
			}
		}
		if len(overrides) == 0 {
			return nil, errors.New("acs v0.1: rewrite changes no argument")
		}
		return map[string]any{"parameter_overrides": overrides}, nil
	case domain.EventToolOutput:
		original := h.outputs["outputs"].([]any)
		rebuilt := domain.RebuildArgs(h.outputs, d.RedactedFields)["outputs"].([]any)
		var redactions []map[string]any
		for i := range original {
			diffLeaves(original[i], rebuilt[i], "/outputs/"+strconv.Itoa(i)+"/value", &redactions)
		}
		if len(redactions) == 0 {
			return nil, errors.New("acs v0.1: rewrite changes no output")
		}
		return map[string]any{"redactions": redactions}, nil
	default:
		return nil, fmt.Errorf("acs v0.1: no rewrite for %s", h.event.Kind)
	}
}

// diffLeaves appends a redaction for every leaf of rebuilt that differs
// from original, addressed by RFC 6901 JSON pointer, in a stable order.
func diffLeaves(original, rebuilt any, pointer string, out *[]map[string]any) {
	switch o := original.(type) {
	case map[string]any:
		r, _ := rebuilt.(map[string]any)
		keys := make([]string, 0, len(o))
		for k := range o {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			diffLeaves(o[k], r[k], pointer+"/"+escapePointer(k), out)
		}
	case []any:
		r, _ := rebuilt.([]any)
		for i := range o {
			if i < len(r) {
				diffLeaves(o[i], r[i], pointer+"/"+strconv.Itoa(i), out)
			}
		}
	default:
		if reflect.DeepEqual(original, rebuilt) {
			return
		}
		replacement, ok := rebuilt.(string)
		if !ok {
			replacement = fmt.Sprint(rebuilt)
		}
		*out = append(*out, map[string]any{"path": pointer, "replacement": replacement})
	}
}

func escapePointer(token string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(token)
}
