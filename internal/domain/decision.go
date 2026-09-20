package domain

// DecisionKind identifies the outcome of evaluating an Event.
type DecisionKind int

const (
	// Allow means nothing blocked or altered the event; it may proceed
	// unchanged.
	Allow DecisionKind = iota
	// Deny means the event must be blocked. Reason explains why.
	Deny
	// Rewrite means the event may proceed, but only after RedactedText
	// (for a prompt) or RedactedFields (for tool arguments) is
	// substituted for the original content.
	Rewrite
)

// String renders a human-readable name for logs and test failures.
func (k DecisionKind) String() string {
	switch k {
	case Allow:
		return "Allow"
	case Deny:
		return "Deny"
	case Rewrite:
		return "Rewrite"
	default:
		return "Unknown"
	}
}

// Decision is the outcome of running an Event through the Policy. Exactly
// one of Reason, RedactedText or RedactedFields is meaningful, depending
// on Kind.
type Decision struct {
	Kind DecisionKind
	// Reason explains a Deny decision to a human or a log line.
	Reason string
	// RedactedText is the replacement text for a Rewrite decision on a
	// PromptSubmit event.
	RedactedText string
	// RedactedFields is the replacement field map for a Rewrite decision
	// on a ToolArgs event.
	RedactedFields map[string]string
}

// AllowDecision builds the zero-friction Allow decision.
func AllowDecision() Decision {
	return Decision{Kind: Allow}
}

// DenyDecision builds a Deny decision carrying a human-readable reason.
func DenyDecision(reason string) Decision {
	return Decision{Kind: Deny, Reason: reason}
}

// RewriteDecision builds a Rewrite decision carrying the redacted
// replacement for prompt text and/or tool argument fields.
func RewriteDecision(redactedText string, redactedFields map[string]string) Decision {
	return Decision{Kind: Rewrite, RedactedText: redactedText, RedactedFields: redactedFields}
}
