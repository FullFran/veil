// Package claudecode adapts between Claude Code's hook JSON wire format
// and veil's host-neutral domain types. Claude Code hooks run as external
// processes: the event arrives as JSON on stdin, the response goes to
// stdout (plus stderr for a blocking reason), and the process exit code
// carries part of the verdict for UserPromptSubmit.
package claudecode

import (
	"encoding/json"
	"fmt"

	"github.com/FullFran/veil/internal/domain"
)

// rawInput mirrors the subset of Claude Code's hook JSON input veil reads.
// Only the fields relevant to UserPromptSubmit and PreToolUse are
// modeled; other hook events are rejected by Decode.
type rawInput struct {
	HookEventName string                 `json:"hook_event_name"`
	UserInput     string                 `json:"user_input"`
	ToolName      string                 `json:"tool_name"`
	ToolInput     map[string]interface{} `json:"tool_input"`
}

// Decode parses raw Claude Code hook JSON into a host-neutral domain.Event.
// It returns an error for any hook_event_name veil does not act on, so an
// unrecognized event fails loudly instead of being silently ignored.
func Decode(raw []byte) (domain.Event, error) {
	var in rawInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return domain.Event{}, fmt.Errorf("claudecode: decode input: %w", err)
	}

	switch in.HookEventName {
	case "UserPromptSubmit":
		return domain.Event{
			Kind: domain.EventPromptSubmit,
			Host: domain.HostClaudeCode,
			Text: in.UserInput,
		}, nil
	case "PreToolUse":
		fields, text := flattenToolInput(in.ToolInput)
		return domain.Event{
			Kind:     domain.EventToolArgs,
			Host:     domain.HostClaudeCode,
			ToolName: in.ToolName,
			Text:     text,
			Fields:   fields,
		}, nil
	default:
		return domain.Event{}, fmt.Errorf("claudecode: unsupported hook_event_name %q", in.HookEventName)
	}
}

// flattenToolInput turns a tool_input JSON object into both a field map
// (for detectors that target a specific argument) and a flattened text
// blob (for detectors that scan free text).
func flattenToolInput(toolInput map[string]interface{}) (fields map[string]string, text string) {
	fields = make(map[string]string, len(toolInput))
	for key, value := range toolInput {
		s := fmt.Sprintf("%v", value)
		fields[key] = s
		text += key + ": " + s + "\n"
	}
	return fields, text
}

// hookSpecificOutput is the shape Claude Code expects nested under
// hookSpecificOutput in a hook's JSON stdout.
type hookSpecificOutput struct {
	HookEventName            string            `json:"hookEventName"`
	PermissionDecision       string            `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string            `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]string `json:"updatedInput,omitempty"`
}

type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

// EncodeResult is what the caller needs to actually respond to Claude
// Code: bytes for stdout and stderr, and the process exit code.
type EncodeResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Encode turns a Decision into the exact bytes and exit code Claude Code
// expects for event's hook type.
func Encode(event domain.Event, decision domain.Decision) (EncodeResult, error) {
	switch event.Kind {
	case domain.EventPromptSubmit:
		return encodePromptSubmit(decision)
	case domain.EventToolArgs:
		return encodeToolArgs(decision)
	default:
		return EncodeResult{}, fmt.Errorf("claudecode: unsupported event kind %q", event.Kind)
	}
}

// encodePromptSubmit encodes a decision for UserPromptSubmit. Claude Code
// blocks a prompt via exit code 2 with the reason on stderr; it rewrites
// via JSON on stdout with exit code 0.
func encodePromptSubmit(decision domain.Decision) (EncodeResult, error) {
	switch decision.Kind {
	case domain.Allow:
		return EncodeResult{ExitCode: 0}, nil
	case domain.Deny:
		return EncodeResult{
			Stderr:   []byte(decision.Reason + "\n"),
			ExitCode: 2,
		}, nil
	case domain.Rewrite:
		b, err := json.Marshal(hookOutput{HookSpecificOutput: hookSpecificOutput{
			HookEventName: "UserPromptSubmit",
			UpdatedInput:  map[string]string{"user_input": decision.RedactedText},
		}})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("claudecode: encode rewrite: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 0}, nil
	default:
		return EncodeResult{}, fmt.Errorf("claudecode: unknown decision kind %v", decision.Kind)
	}
}

// encodeToolArgs encodes a decision for PreToolUse. Both deny and rewrite
// are communicated via JSON on stdout with exit code 0; Claude Code reads
// permissionDecision, not the exit code, for this hook.
func encodeToolArgs(decision domain.Decision) (EncodeResult, error) {
	switch decision.Kind {
	case domain.Allow:
		return EncodeResult{ExitCode: 0}, nil
	case domain.Deny:
		b, err := json.Marshal(hookOutput{HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: decision.Reason,
		}})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("claudecode: encode deny: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 0}, nil
	case domain.Rewrite:
		b, err := json.Marshal(hookOutput{HookSpecificOutput: hookSpecificOutput{
			HookEventName: "PreToolUse",
			UpdatedInput:  decision.RedactedFields,
		}})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("claudecode: encode rewrite: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 0}, nil
	default:
		return EncodeResult{}, fmt.Errorf("claudecode: unknown decision kind %v", decision.Kind)
	}
}
