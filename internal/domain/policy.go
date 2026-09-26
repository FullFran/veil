package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// writeToolNames lists tool names (compared case-insensitively, so this
// covers both Claude Code's "Write"/"Edit"/"MultiEdit" and OpenCode's
// "write"/"edit"/"patch") that write their arguments to disk. A pseudonym
// token reaching one of these tools must be rehydrated back to the real
// value first, so the file on disk holds real data, not a placeholder
// the model was shown instead of it.
var writeToolNames = map[string]bool{
	"write":     true,
	"edit":      true,
	"multiedit": true,
	"patch":     true,
}

func isWriteTool(toolName string) bool {
	return writeToolNames[strings.ToLower(toolName)]
}

// tokenPattern matches one of veil's own pseudonym tokens, e.g.
// "[DNI-001]" or "[IBAN-014]".
var tokenPattern = regexp.MustCompile(`\[[A-Z]+-[0-9]{3}\]`)

// Policy evaluates Events against a Registry of Detectors, turning any
// Findings into a Decision. Findings tagged with a Category are rewritable
// (Policy substitutes a stable pseudonym token for each one); findings
// with no Category (e.g. a secret-path hit) always force a Deny, since
// veil has no safe way to make that payload pass through at all.
type Policy struct {
	registry   *Registry
	pseudonyms PseudonymStore
}

// NewPolicy builds a Policy backed by registry, using pseudonyms to mint
// stable per-session tokens for any rewritable finding.
func NewPolicy(registry *Registry, pseudonyms PseudonymStore) *Policy {
	return &Policy{registry: registry, pseudonyms: pseudonyms}
}

// capabilityFor maps an EventKind to the Capability required to actually
// enforce a decision about it.
func capabilityFor(kind EventKind) (Capability, error) {
	switch kind {
	case EventPromptSubmit:
		return CapabilityPromptBlock, nil
	case EventToolArgs:
		return CapabilityToolArgsBlock, nil
	case EventToolOutput:
		return CapabilityToolOutputRedact, nil
	case EventHistoryText:
		return CapabilityHistoryRewrite, nil
	case EventSystemPrompt:
		return CapabilitySystemPromptRewrite, nil
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
// On success, Evaluate returns exactly one of AllowDecision, a
// DenyDecision, or a RewriteDecision. It never returns a silent Allow when
// the host lacks the capability to enforce the alternative, and it never
// returns a Rewrite built from a guessed or unpseudonymized substitution:
// any failure to mint a pseudonym token fails the whole call closed.
func (p *Policy) Evaluate(event Event) (Decision, error) {
	capability, err := capabilityFor(event.Kind)
	if err != nil {
		return Decision{}, err
	}
	if err := RequireCapability(event.Host, capability); err != nil {
		return Decision{}, err
	}

	decision, err := p.decide(event)
	if err != nil {
		return Decision{}, err
	}

	// A tool call that writes to disk gets one more pass: rehydrate any
	// pseudonym token back to the real value the model never saw, so the
	// file on disk holds real data. This never runs on a Deny: there is
	// nothing to rehydrate into a call veil is blocking outright.
	if decision.Kind != Deny && event.Kind == EventToolArgs && isWriteTool(event.ToolName) {
		return p.rehydrate(event, decision)
	}
	return decision, nil
}

// decide runs the registry's detectors and turns their Findings into an
// Allow, Deny, or Rewrite Decision, without any rehydration.
func (p *Policy) decide(event Event) (Decision, error) {
	findings := p.registry.DetectAll(event)
	if len(findings) == 0 {
		return AllowDecision(), nil
	}

	var denyReasons []string
	var rewritable []Finding
	for _, f := range findings {
		if f.Category == "" {
			denyReasons = append(denyReasons, f.Reason)
			continue
		}
		rewritable = append(rewritable, f)
	}

	// A hard-deny finding always wins, even alongside rewritable ones:
	// veil never partially rewrites an event it must also block outright.
	if len(denyReasons) > 0 {
		return DenyDecision(strings.Join(denyReasons, "; ")), nil
	}

	return p.rewrite(event, rewritable)
}

// rewrite substitutes a stable pseudonym token for every rewritable
// finding's Match in event.Text and every entry of event.Fields, and
// returns the resulting RewriteDecision.
func (p *Policy) rewrite(event Event, findings []Finding) (Decision, error) {
	substitutions := make(map[string]string, len(findings))
	for _, f := range findings {
		if _, done := substitutions[f.Match]; done {
			continue
		}
		token, err := p.pseudonyms.Token(event.SessionID, f.Category, f.Match)
		if err != nil {
			return Decision{}, fmt.Errorf("veil: mint pseudonym token for %s finding: %w", f.Category, err)
		}
		substitutions[f.Match] = token
	}

	redactedText := substituteAll(event.Text, substitutions)

	var redactedFields map[string]string
	if event.Fields != nil {
		redactedFields = make(map[string]string, len(event.Fields))
		for key, value := range event.Fields {
			redactedFields[key] = substituteAll(value, substitutions)
		}
	}

	return RewriteDecision(redactedText, redactedFields), nil
}

// substituteAll replaces every occurrence of each substitutions key in s
// with its mapped token.
func substituteAll(s string, substitutions map[string]string) string {
	for original, token := range substitutions {
		s = strings.ReplaceAll(s, original, token)
	}
	return s
}

// rehydrate reverses every pseudonym token in decision's effective fields
// (its RedactedFields if it is already a Rewrite, or event.Fields
// otherwise) back to the real value the model never saw, for a tool call
// that writes to disk. A token this session never minted is left exactly
// as-is: that is a miss, not a failure. Any store error, however, fails
// the whole call closed.
func (p *Policy) rehydrate(event Event, decision Decision) (Decision, error) {
	fields := decision.RedactedFields
	if fields == nil {
		fields = event.Fields
	}
	if fields == nil {
		return decision, nil
	}

	rehydratedFields := make(map[string]string, len(fields))
	anyChanged := false
	for key, value := range fields {
		newValue, changed, err := p.rehydrateText(event.SessionID, value)
		if err != nil {
			return Decision{}, fmt.Errorf("veil: rehydrate tool argument %q: %w", key, err)
		}
		rehydratedFields[key] = newValue
		if changed {
			anyChanged = true
		}
	}

	if !anyChanged && decision.Kind == Allow {
		return decision, nil
	}

	text := decision.RedactedText
	if text == "" {
		text = event.Text
	}
	rehydratedText, _, err := p.rehydrateText(event.SessionID, text)
	if err != nil {
		return Decision{}, fmt.Errorf("veil: rehydrate tool text: %w", err)
	}

	return RewriteDecision(rehydratedText, rehydratedFields), nil
}

// rehydrateText finds every veil pseudonym token in text and replaces the
// ones this session recognizes with their real original value, leaving
// any unrecognized token exactly as it was. changed reports whether at
// least one token was actually replaced.
func (p *Policy) rehydrateText(sessionID, text string) (result string, changed bool, err error) {
	tokens := tokenPattern.FindAllString(text, -1)
	if len(tokens) == 0 {
		return text, false, nil
	}

	substitutions := make(map[string]string)
	for _, token := range tokens {
		if _, done := substitutions[token]; done {
			continue
		}
		original, found, err := p.pseudonyms.Original(sessionID, token)
		if err != nil {
			return "", false, err
		}
		if !found {
			continue
		}
		substitutions[token] = original
	}

	if len(substitutions) == 0 {
		return text, false, nil
	}
	return substituteAll(text, substitutions), true, nil
}
