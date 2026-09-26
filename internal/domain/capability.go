// Package domain holds veil's host-agnostic decision logic. Nothing in
// this package knows about Claude Code or OpenCode process/plugin details;
// it only knows about Host as an opaque identity used to look up what that
// host can actually enforce.
package domain

import "fmt"

// Host identifies a supported AI coding agent host.
type Host string

const (
	// HostClaudeCode is Anthropic's Claude Code CLI. Its hooks run as
	// external processes: the event arrives as JSON on stdin, the
	// response goes to stdout, and exit code 2 means block.
	HostClaudeCode Host = "claude-code"
	// HostOpenCode is the OpenCode CLI. Its plugins are in-process
	// JS/TS modules that block by throwing and rewrite by mutating the
	// tool call's arguments in place.
	HostOpenCode Host = "opencode"
)

// Capability identifies a single, distinct enforcement guarantee veil can
// be asked to provide for a given host.
type Capability string

const (
	// CapabilityPromptBlock is the ability to block or rewrite a user's
	// typed prompt before the model ever sees it.
	CapabilityPromptBlock Capability = "prompt-block"
	// CapabilityToolArgsBlock is the ability to block or rewrite a tool
	// call's arguments before the tool executes.
	CapabilityToolArgsBlock Capability = "tool-args-block"
	// CapabilityToolOutputRedact is the ability to redact or block a
	// tool's output after the tool has already run.
	CapabilityToolOutputRedact Capability = "tool-output-redact"
	// CapabilityHistoryRewrite is the ability to rewrite (or block) any
	// text or tool-result content resent to the model from prior
	// conversation turns, on every subsequent turn.
	CapabilityHistoryRewrite Capability = "history-rewrite"
	// CapabilitySystemPromptRewrite is the ability to rewrite (or block)
	// the system prompt sent to the model.
	CapabilitySystemPromptRewrite Capability = "system-prompt-rewrite"
)

// capabilityMatrix is the single source of truth for what each host can
// actually enforce. This is code, not a README claim: RequireCapability
// consults exactly this table, and every enforcement path in veil must
// go through it before acting on a Deny or Rewrite decision.
//
// Verified facts encoded here (see project README and
// integration notes's T1 findings, in the downstream harness repo, for
// the sourcing: a local mock OpenAI-compatible provider plus a throwing
// and mutating spike plugin, run against the real, installed OpenCode
// 1.18.32 binary):
//
//   - Claude Code: UserPromptSubmit can block (exit 2) and rewrite the
//     prompt; PreToolUse can block and rewrite tool arguments;
//     PostToolUse is observe-only and cannot redact tool output. Claude
//     Code has no hook that resends prior-turn history or the system
//     prompt through a rewritable hook.
//   - OpenCode: chat.message can block (by throwing, which aborts the
//     request before the model is ever contacted — verified: the mock
//     provider received nothing) and rewrite the typed prompt (by
//     mutating a part's text — verified: the mutated text is what the
//     mock provider received, and what OpenCode's own session storage
//     persisted). tool.execute.before can block (throw) and rewrite tool
//     arguments (mutate output.args), as before. tool.execute.after can
//     redact a tool's output, but ONLY by mutating output.output (and
//     output.metadata.output, when present): throwing there does NOT
//     block anything — the thrown error text just becomes the tool's own
//     result, and the conversation continues with the real tool call
//     already having executed. experimental.chat.messages.transform can
//     rewrite any text or tool-result part resent to the model on every
//     later turn (verified against the real part shape OpenCode sends:
//     {type:"tool", state:{output, metadata:{output}}}).
//     experimental.chat.system.transform can rewrite the system prompt.
var capabilityMatrix = map[Host]map[Capability]bool{
	HostClaudeCode: {
		CapabilityPromptBlock:         true,
		CapabilityToolArgsBlock:       true,
		CapabilityToolOutputRedact:    false,
		CapabilityHistoryRewrite:      false,
		CapabilitySystemPromptRewrite: false,
	},
	HostOpenCode: {
		CapabilityPromptBlock:         true,
		CapabilityToolArgsBlock:       true,
		CapabilityToolOutputRedact:    true,
		CapabilityHistoryRewrite:      true,
		CapabilitySystemPromptRewrite: true,
	},
}

// UnsupportedCapabilityError is returned when a host is asked to enforce a
// guarantee it cannot actually provide. Callers on every enforcement path
// must treat this as a hard failure and propagate it; falling back to an
// implicit Allow defeats the entire purpose of this project.
type UnsupportedCapabilityError struct {
	Host       Host
	Capability Capability
}

func (e *UnsupportedCapabilityError) Error() string {
	return fmt.Sprintf(
		"veil: host %q cannot enforce capability %q; refusing to silently allow",
		e.Host, e.Capability,
	)
}

// Supports reports whether host can enforce capability. An unknown host
// reports false for every capability: an unrecognized host is treated as
// having no guarantees at all, not as fully capable.
func Supports(host Host, capability Capability) bool {
	caps, known := capabilityMatrix[host]
	if !known {
		return false
	}
	return caps[capability]
}

// RequireCapability returns an *UnsupportedCapabilityError when host cannot
// enforce capability, and nil otherwise. Every code path that is about to
// act on a Deny or Rewrite decision must call this first.
func RequireCapability(host Host, capability Capability) error {
	if Supports(host, capability) {
		return nil
	}
	return &UnsupportedCapabilityError{Host: host, Capability: capability}
}
