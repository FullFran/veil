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
	"strings"

	"github.com/FullFran/veil/internal/domain"
)

// rawInput mirrors the JSON the OpenCode shim sends on stdin. Args
// carries a tool.execute.before call's raw (possibly non-string)
// arguments; Fields carries every other event's already-extracted text,
// keyed by a shape specific to that event (see the Decode cases below),
// so the shim can later map a redacted value back to the exact part,
// tool-output field, history part, or system prompt line it came from.
type rawInput struct {
	Event     string                 `json:"event"`
	SessionID string                 `json:"sessionID"`
	Tool      string                 `json:"tool"`
	Args      map[string]interface{} `json:"args"`
	Fields    map[string]string      `json:"fields"`
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
	case "chat.message":
		// The user's typed prompt, as one or more text parts. Verified
		// in T1 to actually reach the model: throwing here aborts the
		// request before the mock provider is ever contacted, and
		// mutating a part's text is what the mock provider (and
		// OpenCode's own session storage) receive instead of the
		// original.
		text := flattenFields(in.Fields)
		return domain.Event{
			Kind:      domain.EventPromptSubmit,
			Host:      domain.HostOpenCode,
			SessionID: in.SessionID,
			Text:      text,
			Fields:    in.Fields,
		}, nil
	case "tool.execute.after":
		// A tool's output, after it already executed. Verified in T1
		// that only mutation (never throwing) actually changes what is
		// resent to the model: throwing there just becomes the tool's
		// own result text and the conversation continues regardless.
		text := flattenFields(in.Fields)
		return domain.Event{
			Kind:      domain.EventToolOutput,
			Host:      domain.HostOpenCode,
			SessionID: in.SessionID,
			ToolName:  in.Tool,
			Text:      text,
			Fields:    in.Fields,
		}, nil
	case "experimental.chat.messages.transform":
		// Every text and tool-result part from prior turns OpenCode is
		// about to resend to the model, keyed by the shim in whatever
		// shape lets it write a redacted value back to the exact part
		// (e.g. "<messageIndex>:<partIndex>:text" or
		// "...:tool" for a part.state.output). veil does not need to
		// understand the key shape; it only needs to preserve it
		// unchanged from Decode's Fields to Encode's RedactedFields.
		text := flattenFields(in.Fields)
		return domain.Event{
			Kind:      domain.EventHistoryText,
			Host:      domain.HostOpenCode,
			SessionID: in.SessionID,
			Text:      text,
			Fields:    in.Fields,
		}, nil
	case "experimental.chat.system.transform":
		// The system prompt, as one string per array index.
		text := flattenFields(in.Fields)
		return domain.Event{
			Kind:      domain.EventSystemPrompt,
			Host:      domain.HostOpenCode,
			SessionID: in.SessionID,
			Text:      text,
			Fields:    in.Fields,
		}, nil
	default:
		return domain.Event{}, fmt.Errorf("opencode: unsupported event %q", in.Event)
	}
}

// flattenFields concatenates an already-extracted field map into a single
// text blob for detectors that scan free text. Map iteration order is
// unspecified, which is fine here: nothing downstream depends on the
// concatenation's order, only on every value being present somewhere in
// it.
func flattenFields(fields map[string]string) string {
	var b strings.Builder
	for key, value := range fields {
		b.WriteString(key)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\n")
	}
	return b.String()
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
