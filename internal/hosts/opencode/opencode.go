// Package opencode adapts between the JSON contract used by veil's
// OpenCode shim (adapters/opencode) and veil's host-neutral domain types.
//
// Unlike Claude Code, OpenCode plugins are in-process JS/TS modules: the
// shim spawns the veil binary per tool call and communicates over
// stdin/stdout, with the exit code signaling allow versus deny.
//
// This package intentionally has no decoder for a prompt-level event.
// OpenCode exposes no hook that reaches the user's typed prompt at all
// (there is no tool.execute.before equivalent for prompt text), so there
// is no real wire format to decode here, and adding a synthetic one would
// misrepresent a capability OpenCode does not have. The proof that veil
// still refuses to silently allow a prompt-level guarantee on OpenCode
// lives in internal/domain/leak_test.go, built directly against
// domain.HostOpenCode.
package opencode

import (
	"encoding/json"
	"fmt"

	"github.com/FullFran/veil/internal/domain"
)

// rawInput mirrors the JSON the OpenCode shim sends on stdin for a
// tool.execute.before call.
type rawInput struct {
	Event     string                 `json:"event"`
	SessionID string                 `json:"sessionID"`
	Tool      string                 `json:"tool"`
	Args      map[string]interface{} `json:"args"`
}

// Decode parses the shim's JSON into a host-neutral domain.Event. It
// returns an error for any event veil does not act on.
func Decode(raw []byte) (domain.Event, error) {
	var in rawInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return domain.Event{}, fmt.Errorf("opencode: decode input: %w", err)
	}

	switch in.Event {
	case "tool.execute.before":
		fields, text := flattenArgs(in.Args)
		return domain.Event{
			Kind:      domain.EventToolArgs,
			Host:      domain.HostOpenCode,
			SessionID: in.SessionID,
			ToolName:  in.Tool,
			Text:      text,
			Fields:    fields,
		}, nil
	default:
		return domain.Event{}, fmt.Errorf("opencode: unsupported event %q", in.Event)
	}
}

// flattenArgs turns a tool call's args object into both a field map (for
// detectors that target a specific argument) and a flattened text blob
// (for detectors that scan free text).
func flattenArgs(args map[string]interface{}) (fields map[string]string, text string) {
	fields = make(map[string]string, len(args))
	for key, value := range args {
		s := fmt.Sprintf("%v", value)
		fields[key] = s
		text += key + ": " + s + "\n"
	}
	return fields, text
}

// output is the JSON shape the OpenCode shim expects on stdout.
type output struct {
	Action string            `json:"action"`
	Reason string            `json:"reason,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

// EncodeResult is what the caller needs to actually respond to the shim:
// stdout bytes and the process exit code.
type EncodeResult struct {
	Stdout   []byte
	ExitCode int
}

// Encode turns a Decision into the exact bytes and exit code the OpenCode
// shim expects. Exit code 0 means the tool call may proceed (allow or
// rewrite); a non-zero exit code means the shim must throw to block it.
func Encode(decision domain.Decision) (EncodeResult, error) {
	switch decision.Kind {
	case domain.Allow:
		b, err := json.Marshal(output{Action: "allow"})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("opencode: encode allow: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 0}, nil
	case domain.Deny:
		b, err := json.Marshal(output{Action: "deny", Reason: decision.Reason})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("opencode: encode deny: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 1}, nil
	case domain.Rewrite:
		b, err := json.Marshal(output{Action: "rewrite", Args: decision.RedactedFields})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("opencode: encode rewrite: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 0}, nil
	default:
		return EncodeResult{}, fmt.Errorf("opencode: unknown decision kind %v", decision.Kind)
	}
}
