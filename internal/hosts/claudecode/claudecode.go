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
	SessionID     string                 `json:"session_id"`
	UserInput     string                 `json:"user_input"`
	ToolName      string                 `json:"tool_name"`
	ToolInput     map[string]interface{} `json:"tool_input"`
}

// Decode parses raw Claude Code hook JSON into a host-neutral domain.Event.
// It returns an error for any hook_event_name veil does not act on, so an
// unrecognized event fails loudly instead of being silently ignored.
func Decode(raw []byte) (domain.Event, error) {
	var in rawInput
	if err := domain.DecodeJSON(raw, &in); err != nil {
		return domain.Event{}, fmt.Errorf("claudecode: decode input: %w", err)
	}

	switch in.HookEventName {
	case "UserPromptSubmit":
		return domain.Event{
			Kind:      domain.EventPromptSubmit,
			Host:      domain.HostClaudeCode,
			SessionID: in.SessionID,
			Text:      in.UserInput,
		}, nil
	case "PreToolUse":
		fields, text := domain.FlattenArgs(in.ToolInput)
		return domain.Event{
			Kind:      domain.EventToolArgs,
			Host:      domain.HostClaudeCode,
			SessionID: in.SessionID,
			ToolName:  in.ToolName,
			Text:      text,
			Fields:    fields,
			Args:      in.ToolInput,
		}, nil
	default:
		return domain.Event{}, fmt.Errorf("claudecode: unsupported hook_event_name %q", in.HookEventName)
	}
}

// hookSpecificOutput is the shape Claude Code expects nested under
// hookSpecificOutput in a hook's JSON stdout.
type hookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

// FailureExitCode is the exit code veil uses when it fails on this host.
// Claude Code treats exit 2 as a blocking error and every other nonzero
// exit as a non-blocking one (the prompt or tool call proceeds), so the
// generic failed-closed class (1) would fail open here. 2 is the only
// code that blocks; the problem line on stderr tells a failure apart from
// a UserPromptSubmit deny, which also exits 2.
const FailureExitCode = 2

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
		return encodeToolArgs(event, decision)
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
			UpdatedInput:  map[string]any{"user_input": decision.RedactedText},
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
func encodeToolArgs(event domain.Event, decision domain.Decision) (EncodeResult, error) {
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
			UpdatedInput:  domain.RebuildArgs(event.Args, decision.RedactedFields),
		}})
		if err != nil {
			return EncodeResult{}, fmt.Errorf("claudecode: encode rewrite: %w", err)
		}
		return EncodeResult{Stdout: b, ExitCode: 0}, nil
	default:
		return EncodeResult{}, fmt.Errorf("claudecode: unknown decision kind %v", decision.Kind)
	}
}
