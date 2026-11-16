package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/eval"
	"github.com/FullFran/veil/internal/hosts/acs"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// acsTemplates is one request payload per evaluated hook with every
// member its pinned schema defines, so each string position exists.
var acsTemplates = map[string]string{
	"steps/agentTrigger": `{"trigger_type":"user_message","trigger_source":{"channel":"chat","message":"hola"},` +
		`"intent":{"raw":"abre el informe","parsed":[{"tool":"file_read","operation":"read","resource":"informe.md"}],"scope_mode":"strict",` +
		`"parser_provenance":{"origin":"system","provenance_id":"p-1"}}}`,
	"steps/userMessage": `{"content":[{"type":"text","value":"hola"},{"type":"text","value":{"nota":"texto"}}],"extra":"x"}`,
	"steps/knowledgeRetrieval": `{"query":{"value":"busca"},"source":{"name":"kb","type":"vector_db","version":"1"},` +
		`"results":[{"value":"texto","source_id":"doc-1","score":0.5}]}`,
	"steps/memoryContextRetrieval": `{"query":{"value":"busca"},"memory_store":{"name":"m","scope":"session"},` +
		`"results":[{"memory_id":"m-1","value":"texto","stored_at":"2026-09-09T14:00:00Z"}]}`,
	"steps/toolCallRequest": `{"tool":{"name":"file_read","version":"1","provider":"p"},"operation":"read","capability":"fs",` +
		`"arguments":{"path":{"value":"/tmp/a"},"opts":{"value":{"mode":"r","tags":["a"]}}},"raw_command":"cat /tmp/a",` +
		`"intent":{"description":"lee","goal":"resumen"},"extra":"x"}`,
	"steps/toolCallResult": `{"tool":{"name":"file_read"},"operation":"read","exit_status":"success","outputs":[{"value":"texto"}],"duration_ms":3}`,
}

// position is where a value goes in params: a string leaf, or the name
// of a member (key true).
type position struct {
	path []any // member names and item indexes from params
	key  bool
}

func (p position) String() string {
	s := ""
	for _, step := range p.path {
		s += "/" + fmt.Sprint(step)
	}
	if p.key {
		return "key " + s
	}
	return s
}

// positions lists every string leaf and member name under payload and
// metadata (session_id aside, which veil needs to key its pseudonyms)
// and an extra params member: everything but the structural members
// veil reads itself (acs_version, request_id, timestamp, signature).
func positions(params map[string]any) []position {
	var out []position
	var walk func(v any, path []any)
	walk = func(v any, path []any) {
		switch t := v.(type) {
		case map[string]any:
			for _, k := range slices.Sorted(func(yield func(string) bool) {
				for k := range t {
					if !yield(k) {
						return
					}
				}
			}) {
				child := append(slices.Clone(path), k)
				if len(path) == 1 && path[0] == "metadata" && k == "session_id" {
					continue
				}
				out = append(out, position{path: child, key: true})
				walk(t[k], child)
			}
		case []any:
			for i, item := range t {
				walk(item, append(slices.Clone(path), i))
			}
		case string:
			out = append(out, position{path: path})
		}
	}
	for _, member := range []string{"payload", "metadata", "note"} {
		out = append(out, position{path: []any{member}, key: member == "note"})
		walk(params[member], []any{member})
	}
	return slices.DeleteFunc(out, func(p position) bool {
		return len(p.path) == 1 && p.path[0] != "note"
	})
}

// place returns a copy of params with value at p.
func place(t *testing.T, params map[string]any, p position, value string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(params)
	var cp map[string]any
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	var parent any = cp
	for _, step := range p.path[:len(p.path)-1] {
		switch s := step.(type) {
		case string:
			parent = parent.(map[string]any)[s]
		case int:
			parent = parent.([]any)[s]
		}
	}
	switch last := p.path[len(p.path)-1].(type) {
	case string:
		m := parent.(map[string]any)
		if p.key {
			m[value] = m[last]
			delete(m, last)
		} else {
			m[last] = value
		}
	case int:
		parent.([]any)[last] = value
	}
	return cp
}

// TestRun_ACS_SpanishCorpus_NeverPassesInClear places every gold value of
// the Spanish corpus, one at a time, in every string position and member
// name of every evaluated hook, and asks the real engine through the ACS
// server. Whatever the decision, the value must not be in the response,
// nor anywhere in the request the agent goes on with once the decision is
// applied. A value the engine misses even alone (the corpus baseline
// recall is below 1 for some labels) is reported, not placed.
func TestRun_ACS_SpanishCorpus_NeverPassesInClear(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus sweep")
	}
	isolateACS(t)
	dir := filepath.Join("..", "..", "testdata", "corpus", "es", "v1")
	corpus, err := eval.LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_CATALOG", corpus.CatalogPath)
	e, err := newEngine()
	if err != nil {
		t.Fatal(err)
	}
	cfg := port.Config{Guard: func(ev domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
		return e.decide(domain.HostACS, ev)
	}}
	const session = "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"

	seen := map[string]bool{}
	var values []string
	missed := map[string]int{}
	for _, c := range corpus.Cases {
		for _, g := range c.Gold {
			v := string([]rune(c.Units[g.Unit])[g.Start:g.End])
			if seen[v] {
				continue
			}
			seen[v] = true
			d, _, code := e.decide(domain.HostACS, domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostACS,
				SessionID: session, Text: v, Fields: map[string]string{"v": v}})
			if code != "" {
				t.Fatalf("engine failed on %s: %s", g.Label, code)
			}
			if d.Kind == domain.Allow {
				missed[g.Label]++
				continue
			}
			values = append(values, v)
		}
	}
	t.Logf("%d distinct gold values placed; missed even alone, by label: %v", len(values), missed)
	if len(values) == 0 {
		t.Fatal("no corpus value to place")
	}

	now := time.Now().UTC()
	runs := 0
	outcomes := map[string]int{}
	for _, method := range slices.Sorted(func(yield func(string) bool) {
		for m := range acsTemplates {
			if !yield(m) {
				return
			}
		}
	}) {
		var payload any
		if err := json.Unmarshal([]byte(acsTemplates[method]), &payload); err != nil {
			t.Fatal(err)
		}
		params := map[string]any{
			"acs_version": "0.1.0",
			"request_id":  acsRequestID,
			"timestamp":   now.Format(time.RFC3339),
			"metadata":    map[string]any{"agent_id": "asistente", "session_id": session, "user": "u-1"},
			"payload":     payload,
			"note":        "nota",
		}
		for _, p := range positions(params) {
			for _, v := range values {
				placed := place(t, params, p, v)
				raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": placed})
				if err != nil {
					t.Fatal(err)
				}
				reply := acs.NewServer(cfg).Answer(raw)
				runs++
				where := method + " " + p.String()
				if strings.Contains(string(reply.Body), v) {
					t.Fatalf("%s: the response carries %q", where, v)
				}
				var resp struct {
					Result map[string]any `json:"result"`
				}
				if err := json.Unmarshal(reply.Body, &resp); err != nil || resp.Result == nil {
					t.Fatalf("%s: no decision: %s", where, reply.Body)
				}
				outcome, _ := resp.Result["decision"].(string)
				if codes, ok := resp.Result["reason_codes"].([]any); ok && len(codes) > 0 {
					outcome += " " + fmt.Sprint(codes[0])
				}
				outcomes[outcome]++
				if effective := applyACSDecision(t, raw, resp.Result); carries(effective, v) {
					t.Fatalf("%s: %s and the request goes on with %q", where, resp.Result["decision"], v)
				}
			}
		}
	}
	t.Logf("%d requests answered: %v", runs, outcomes)
}

// applyACSDecision is the request the Observed Agent goes on with after a
// result: nothing on deny, the request on allow, and on modify the request
// with parameter_overrides and redactions applied.
func applyACSDecision(t *testing.T, request []byte, result map[string]any) any {
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
		t.Fatalf("decision = %v", result["decision"])
	}
	payload := req["params"].(map[string]any)["payload"].(map[string]any)
	mods := result["modifications"].(map[string]any)
	if overrides, ok := mods["parameter_overrides"].(map[string]any); ok {
		for name, value := range overrides {
			payload["arguments"].(map[string]any)[name].(map[string]any)["value"] = value
		}
	}
	redactions, _ := mods["redactions"].([]any)
	for _, r := range redactions {
		r := r.(map[string]any)
		tokens := strings.Split(r["path"].(string), "/")[1:]
		var doc any = payload
		for i, tok := range tokens {
			tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
			last := i == len(tokens)-1
			switch d := doc.(type) {
			case map[string]any:
				if last {
					d[tok] = r["replacement"]
				}
				doc = d[tok]
			case []any:
				n, err := strconv.Atoi(tok)
				if err != nil || n >= len(d) {
					t.Fatalf("redaction %v addresses nothing", r)
				}
				if last {
					d[n] = r["replacement"]
				}
				doc = d[n]
			default:
				t.Fatalf("redaction %v goes through a leaf", r)
			}
		}
	}
	return req
}

// carries reports whether s is in any string leaf or member name of v.
func carries(v any, s string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if strings.Contains(k, s) || carries(child, s) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(t, func(child any) bool { return carries(child, s) })
	case string:
		return strings.Contains(t, s)
	}
	return false
}
