package domain

import (
	"fmt"
	"regexp"
	"sort"
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
	decision, _, err := p.Assess(event)
	return decision, err
}

// Assess is Evaluate that also returns the findings the decision was
// made on, so a caller that records evidence never runs the detectors a
// second time (a detector may be a model in another process: a second
// call costs latency and may fail or answer differently). On error it
// returns the zero Decision and no findings.
func (p *Policy) Assess(event Event) (Decision, []Finding, error) {
	capability, err := capabilityFor(event.Kind)
	if err != nil {
		return Decision{}, nil, err
	}
	if err := RequireCapability(event.Host, capability); err != nil {
		return Decision{}, nil, err
	}

	findings, err := p.registry.DetectAll(event)
	if err != nil {
		return Decision{}, nil, err
	}
	decision, err := p.decide(event, findings)
	if err != nil {
		return Decision{}, nil, err
	}

	// A tool call that writes to disk gets one more pass: rehydrate any
	// pseudonym token back to the real value the model never saw, so the
	// file on disk holds real data. This never runs on a Deny: there is
	// nothing to rehydrate into a call veil is blocking outright.
	if decision.Kind != Deny && event.Kind == EventToolArgs && isWriteTool(event.ToolName) {
		decision, err = p.rehydrate(event, decision)
		if err != nil {
			return Decision{}, nil, err
		}
	}
	return decision, findings, nil
}

// decide turns findings into an Allow, Deny, or Rewrite Decision,
// without any rehydration.
func (p *Policy) decide(event Event, findings []Finding) (Decision, error) {
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
	findings = withOverlapRuns(event, findings)
	firstWritten := firstWrittenForms(event.Text, findings)
	substitutions := make(map[string]string, len(findings))
	for _, f := range findings {
		if _, done := substitutions[f.Match]; done {
			continue
		}
		key := findingKey(f)
		token, err := p.pseudonyms.TokenFor(event.SessionID, f.Category, key, firstWritten[f.Category+":"+key])
		if err != nil {
			return Decision{}, fmt.Errorf("veil: mint pseudonym token for %s finding: %w", f.Category, err)
		}
		substitutions[f.Match] = token
	}

	// One replacer for the text and every field: building it costs the
	// number of substitutions, so one per field would make the rewrite
	// fields × findings.
	replacer := newSubstituter(substitutions)
	redactedText := replacer.Replace(event.Text)

	var redactedFields map[string]string
	if event.Fields != nil {
		redactedFields = make(map[string]string, len(event.Fields))
		for key, value := range event.Fields {
			redactedFields[key] = replacer.Replace(value)
		}
	}

	return RewriteDecision(redactedText, redactedFields), nil
}

func findingKey(f Finding) string {
	if f.Key == "" {
		return f.Match
	}
	return f.Key
}

// firstWrittenForms returns, per "category:key", the written form that
// comes first in text, so the form a token keeps for rehydration is the
// first one the model was shown a token for, whatever order the
// detectors reported their findings in. A form that is not in text (only
// in a field) comes after every form that is.
func firstWrittenForms(text string, findings []Finding) map[string]string {
	first := make(map[string]string, len(findings))
	at := make(map[string]int, len(findings))
	for _, f := range findings {
		id := f.Category + ":" + findingKey(f)
		pos := strings.Index(text, f.Match)
		if pos < 0 {
			pos = len(text)
		}
		if prev, seen := at[id]; !seen || pos < prev {
			first[id], at[id] = f.Match, pos
		}
	}
	return first
}

// substituteAll replaces every occurrence of each substitutions key in s
// with its mapped token, in one left-to-right pass that prefers the
// longest key at each position. A key that is part of a longer one
// ("Juan García" inside "Juan García-López") therefore never cuts the
// longer match apart, which would leave the rest in clear, and a token
// already written is never scanned again.
func substituteAll(s string, substitutions map[string]string) string {
	return newSubstituter(substitutions).Replace(s)
}

// newSubstituter is the replacer substituteAll applies, built once so it
// can be reused across many strings.
func newSubstituter(substitutions map[string]string) *strings.Replacer {
	originals := make([]string, 0, len(substitutions))
	for original := range substitutions {
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool {
		if len(originals[i]) != len(originals[j]) {
			return len(originals[i]) > len(originals[j])
		}
		return originals[i] < originals[j]
	})
	pairs := make([]string, 0, 2*len(originals))
	for _, original := range originals {
		pairs = append(pairs, original, substitutions[original])
	}
	return strings.NewReplacer(pairs...)
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
