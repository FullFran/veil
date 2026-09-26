package domain

// EventKind identifies the kind of host event being inspected.
type EventKind string

const (
	// EventPromptSubmit represents a user-typed prompt submitted to the
	// model, before the model has seen it.
	EventPromptSubmit EventKind = "PromptSubmit"
	// EventToolArgs represents the arguments of a tool call about to
	// execute.
	EventToolArgs EventKind = "ToolArgs"
	// EventToolOutput represents a tool call's output after it has
	// already executed, before that output is sent back to the model.
	EventToolOutput EventKind = "ToolOutput"
	// EventHistoryText represents the full set of text and tool-result
	// parts from prior conversation turns that a host is about to resend
	// to the model on this turn.
	EventHistoryText EventKind = "HistoryText"
	// EventSystemPrompt represents the system prompt strings a host is
	// about to send to the model.
	EventSystemPrompt EventKind = "SystemPrompt"
)

// Event is the host-neutral representation of something veil is asked to
// inspect. Domain code must never know which host (Claude Code, OpenCode,
// or any future host) produced it; Host is carried only as an opaque
// identity for capability lookups.
type Event struct {
	// Kind identifies what this event represents.
	Kind EventKind
	// Host identifies which host adapter produced this event. It is
	// used only to check capability support before acting on a
	// decision; it must never change detection logic itself.
	Host Host
	// ToolName is set when Kind is EventToolArgs. It is the name of the
	// tool about to be invoked, in whatever casing the host uses (e.g.
	// "Read" on Claude Code, "read" on OpenCode).
	ToolName string
	// Text is the raw text to scan with text-based detectors: the
	// prompt text for EventPromptSubmit, or a flattened representation
	// of the tool arguments for EventToolArgs.
	Text string
	// Fields carries structured tool argument key/value pairs when Kind
	// is EventToolArgs, so detectors can target specific fields (e.g. a
	// file path field) without re-parsing Text.
	Fields map[string]string
	// SessionID identifies the host's conversation/session, when the
	// host exposes one. Policy uses it only to scope a PseudonymStore's
	// per-session token mapping; detection logic must never branch on
	// it. Empty means the host did not supply one.
	SessionID string
}
