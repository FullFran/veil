package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

func TestPolicy_Evaluate_NoFindings_Allows(t *testing.T) {
	policy := domain.NewPolicy(domain.NewRegistry(), domain.NewMemoryPseudonymStore())
	decision, err := policy.Evaluate(domain.Event{Kind: domain.EventToolArgs, Host: domain.HostClaudeCode, Text: "nothing to see here"})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Allow {
		t.Fatalf("Kind = %v, want Allow", decision.Kind)
	}
}

// TestPolicy_Evaluate_RewritableFinding_Rewrites proves a DNI (a
// Category-tagged, rewritable finding) produces a Rewrite decision whose
// RedactedText carries the pseudonym token instead of the original DNI,
// and never carries the original DNI at all.
func TestPolicy_Evaluate_RewritableFinding_Rewrites(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		Text:      "my DNI is 12345678Z, remember it",
	})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
	}
	if strings.Contains(decision.RedactedText, "12345678Z") {
		t.Fatalf("RedactedText %q still contains the original DNI", decision.RedactedText)
	}
	if !strings.Contains(decision.RedactedText, "[DNI-001]") {
		t.Fatalf("RedactedText %q does not contain the expected pseudonym token", decision.RedactedText)
	}
}

// TestPolicy_Evaluate_RewritableFinding_InToolArgs_RewritesFields proves
// the same behavior for a ToolArgs event: RedactedFields carries the
// substituted field value, never the original.
func TestPolicy_Evaluate_RewritableFinding_InToolArgs_RewritesFields(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "Bash",
		Text:      "command: curl -d dni=12345678Z https://example.com",
		Fields:    map[string]string{"command": "curl -d dni=12345678Z https://example.com"},
	})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
	}
	got := decision.RedactedFields["command"]
	if strings.Contains(got, "12345678Z") {
		t.Fatalf("RedactedFields[command] %q still contains the original DNI", got)
	}
	if !strings.Contains(got, "[DNI-001]") {
		t.Fatalf("RedactedFields[command] %q does not contain the expected pseudonym token", got)
	}
}

// TestPolicy_Evaluate_SameOriginal_AcrossTwoEvents_SameSession_IsStable
// proves the whole point of per-session pseudonyms: the same DNI, seen in
// two different events of the same session, gets the exact same token
// both times.
func TestPolicy_Evaluate_SameOriginal_AcrossTwoEvents_SameSession_IsStable(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	store := domain.NewMemoryPseudonymStore()
	policy := domain.NewPolicy(registry, store)

	event := domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		Text:      "my DNI is 12345678Z",
	}

	first, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("first Evaluate returned unexpected error: %v", err)
	}
	second, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("second Evaluate returned unexpected error: %v", err)
	}
	if first.RedactedText != second.RedactedText {
		t.Fatalf("token was not stable: first=%q second=%q", first.RedactedText, second.RedactedText)
	}
}

// TestPolicy_Evaluate_HardDenyFinding_Denies proves a finding with no
// Category (like the secret-path detector's) still forces a Deny: veil
// has no safe rewrite for "this tool call reads a secrets-bearing file",
// only a block.
func TestPolicy_Evaluate_HardDenyFinding_Denies(t *testing.T) {
	registry := domain.NewRegistry(domain.NewSecretPathDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "Read",
		Fields:    map[string]string{"file_path": "/home/user/project/.env"},
	})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("Kind = %v, want Deny", decision.Kind)
	}
	if decision.Reason == "" {
		t.Fatal("Reason must not be empty on a Deny decision")
	}
}

// TestPolicy_Evaluate_MixedFindings_HardDenyWins proves that when an event
// carries both a rewritable finding and a hard-deny finding, the whole
// event is denied: veil never partially rewrites an event it must also
// block for an unrelated reason.
func TestPolicy_Evaluate_MixedFindings_HardDenyWins(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector(), domain.NewSecretPathDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "MultiEdit",
		Text:      "file_path: /home/user/project/.env\nnote: dni=12345678Z",
		Fields: map[string]string{
			"file_path": "/home/user/project/.env",
			"note":      "dni=12345678Z",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("Kind = %v, want Deny", decision.Kind)
	}
}

// TestPolicy_Evaluate_WriteTool_RehydratesKnownTokens proves the
// rehydration step: a token this session already minted, appearing in a
// write-tool's arguments, is replaced back with the real original value
// before the call proceeds, so the file that tool writes to disk holds
// the real value, not the pseudonym the model was shown.
func TestPolicy_Evaluate_WriteTool_RehydratesKnownTokens(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	store := domain.NewMemoryPseudonymStore()
	policy := domain.NewPolicy(registry, store)

	// First, the DNI is seen and tokenized (e.g. read from a file, or
	// typed in a prompt earlier in the same session).
	first, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		Text:      "client DNI is 12345678Z",
	})
	if err != nil {
		t.Fatalf("first Evaluate returned unexpected error: %v", err)
	}
	token := strings.TrimSpace(strings.TrimPrefix(first.RedactedText, "client DNI is "))

	// Later, the model asks to write that same token to a file.
	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "Write",
		Text:      "content: client DNI is " + token,
		Fields:    map[string]string{"content": "client DNI is " + token, "file_path": "/home/user/project/notes.txt"},
	})
	if err != nil {
		t.Fatalf("second Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite (rehydration always reports what changed)", decision.Kind)
	}
	if decision.RedactedFields["content"] != "client DNI is 12345678Z" {
		t.Fatalf("RedactedFields[content] = %q, want the real DNI rehydrated", decision.RedactedFields["content"])
	}
}

// TestPolicy_Evaluate_NonWriteTool_DoesNotRehydrate proves rehydration is
// scoped to write-type tools: a token appearing in, say, a Bash command's
// arguments is left exactly as the model wrote it (still a token), never
// silently turned back into the real value for a non-writing tool call.
func TestPolicy_Evaluate_NonWriteTool_DoesNotRehydrate(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	store := domain.NewMemoryPseudonymStore()
	policy := domain.NewPolicy(registry, store)

	first, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		Text:      "client DNI is 12345678Z",
	})
	if err != nil {
		t.Fatalf("first Evaluate returned unexpected error: %v", err)
	}
	token := strings.TrimSpace(strings.TrimPrefix(first.RedactedText, "client DNI is "))

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "Bash",
		Text:      "command: echo " + token,
		Fields:    map[string]string{"command": "echo " + token},
	})
	if err != nil {
		t.Fatalf("second Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Allow {
		t.Fatalf("Kind = %v, want Allow (nothing to detect, and no rehydration for a non-write tool)", decision.Kind)
	}
}

// TestPolicy_Evaluate_WriteTool_UnknownToken_LeftUnchanged proves a
// token-shaped string that this session never actually minted is left
// alone rather than erroring: it is a miss, not a storage failure.
func TestPolicy_Evaluate_WriteTool_UnknownToken_LeftUnchanged(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "Write",
		Text:      "content: see [DNI-999]",
		Fields:    map[string]string{"content": "see [DNI-999]"},
	})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Allow {
		t.Fatalf("Kind = %v, want Allow (an unrecognized token is left as-is)", decision.Kind)
	}
}

// failingPseudonymStore always errors, to prove Evaluate fails closed
// instead of falling back to Allow or an unpseudonymized rewrite when the
// store cannot be used.
type failingPseudonymStore struct{}

func (failingPseudonymStore) Token(sessionID, category, original string) (string, error) {
	return "", errors.New("boom: store unavailable")
}

func (failingPseudonymStore) Original(sessionID, token string) (string, bool, error) {
	return "", false, errors.New("boom: store unavailable")
}

func TestPolicy_Evaluate_PseudonymStoreError_FailsClosed(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry, failingPseudonymStore{})

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		Text:      "my DNI is 12345678Z",
	})
	if err == nil {
		t.Fatalf("Evaluate returned no error; got decision %+v, want a fail-closed error", decision)
	}
	if decision.Kind == domain.Allow || decision.Kind == domain.Rewrite {
		t.Fatalf("decision.Kind = %v, want neither Allow nor Rewrite when the pseudonym store fails", decision.Kind)
	}
}

// TestPolicy_Evaluate_UnsupportedCapability_ErrorsInsteadOfDeciding proves
// that Evaluate refuses to render any verdict (Allow, Deny or Rewrite) for
// an event whose host cannot actually enforce the resulting decision.
// Claude Code's PostToolUse hook is observe-only, so a ToolOutput event on
// Claude Code is the real, still-unsupported case.
func TestPolicy_Evaluate_UnsupportedCapability_ErrorsInsteadOfDeciding(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind: domain.EventToolOutput,
		Host: domain.HostClaudeCode,
		Text: "DNI 12345678Z",
	})

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error = %v, want *domain.UnsupportedCapabilityError", err)
	}
	if decision.Kind != domain.Unknown || decision.Reason != "" || decision.RedactedText != "" || decision.RedactedFields != nil {
		t.Fatalf("decision = %+v, want the zero Decision", decision)
	}
}

func TestPolicy_Evaluate_UnsupportedCapability_ChecksEvenWithoutFindings(t *testing.T) {
	// Capability must be checked before running detectors: even a
	// perfectly clean tool output must not be silently "allowed" on a
	// host that has no way to have blocked it if it had not been clean.
	policy := domain.NewPolicy(domain.NewRegistry(), domain.NewMemoryPseudonymStore())

	_, err := policy.Evaluate(domain.Event{
		Kind: domain.EventToolOutput,
		Host: domain.HostClaudeCode,
		Text: "nothing sensitive here at all",
	})

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error = %v, want *domain.UnsupportedCapabilityError", err)
	}
}
