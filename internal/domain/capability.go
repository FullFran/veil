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
)

// capabilityMatrix is the single source of truth for what each host can
// actually enforce. This is code, not a README claim: RequireCapability
// consults exactly this table, and every enforcement path in veil must
// go through it before acting on a Deny or Rewrite decision.
//
// Verified facts encoded here (see project README for the sourcing):
//
//   - Claude Code: UserPromptSubmit can block (exit 2) and rewrite the
//     prompt; PreToolUse can block and rewrite tool arguments;
//     PostToolUse is observe-only and cannot redact tool output.
//   - OpenCode: there is no documented hook that reaches the typed
//     prompt at all; tool.execute.before can block (by throwing) and
//     rewrite tool arguments (by mutating output.args);
//     tool.execute.after's ability to mutate the tool result is
//     unverified and is therefore treated as unsupported.
var capabilityMatrix = map[Host]map[Capability]bool{
	HostClaudeCode: {
		CapabilityPromptBlock:      true,
		CapabilityToolArgsBlock:    true,
		CapabilityToolOutputRedact: false,
	},
	HostOpenCode: {
		CapabilityPromptBlock:      false,
		CapabilityToolArgsBlock:    true,
		CapabilityToolOutputRedact: false,
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
