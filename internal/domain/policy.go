package domain

import (
	"fmt"
	"strings"
)

// Policy evaluates Events against a Registry of Detectors and turns any
// Findings into a Decision.
type Policy struct {
	registry *Registry
}

// NewPolicy builds a Policy backed by registry.
func NewPolicy(registry *Registry) *Policy {
	return &Policy{registry: registry}
}

// capabilityFor maps an EventKind to the Capability required to actually
// enforce a decision about it.
func capabilityFor(kind EventKind) (Capability, error) {
	switch kind {
	case EventPromptSubmit:
		return CapabilityPromptBlock, nil
	case EventToolArgs:
		return CapabilityToolArgsBlock, nil
	default:
		return "", fmt.Errorf("veil: unknown event kind %q", kind)
	}
}

// Evaluate inspects event and returns the Decision veil should enforce.
//
// Evaluate checks the host's capability to enforce a verdict about this
// kind of event BEFORE running any detector, and for any event where that
// capability is missing, checks it EVEN IF there turns out to be nothing
// to report. A host that cannot have blocked a leak must not be told
// "allowed" just because this particular input happened to be clean: the
// guarantee itself is what is unsupported, not the specific verdict.
//
// On success, Evaluate returns exactly one of AllowDecision or a
// DenyDecision explaining what was found. It never returns a silent Allow
// when the host lacks the capability to enforce the alternative.
func (p *Policy) Evaluate(event Event) (Decision, error) {
	capability, err := capabilityFor(event.Kind)
	if err != nil {
		return Decision{}, err
	}
	if err := RequireCapability(event.Host, capability); err != nil {
		return Decision{}, err
	}

	findings := p.registry.DetectAll(event)
	if len(findings) == 0 {
		return AllowDecision(), nil
	}

	reasons := make([]string, 0, len(findings))
	for _, f := range findings {
		reasons = append(reasons, f.Reason)
	}
	return DenyDecision(strings.Join(reasons, "; ")), nil
}
