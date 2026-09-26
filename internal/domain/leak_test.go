package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// newPolicy builds the standard veil policy: every detector veil ships,
// wired into a fresh registry, with a fresh in-memory pseudonym store.
// This mirrors how cmd/veil wires the policy in production (modulo the
// store being file-backed there, for the reasons documented on
// internal/pseudonymstore), so these tests exercise the same detection
// surface a real hook invocation would.
func newPolicy() *domain.Policy {
	registry := domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewSecretPathDetector(),
	)
	return domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())
}

// 1. A valid Spanish DNI in a tool argument is a rewritable finding: the
// call proceeds, but only with the DNI replaced by a stable pseudonym
// token, never with the original value.
func TestLeak_DNIInToolArgument_IsRewritten(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		ToolName:  "Bash",
		Text:      "command: curl -d dni=12345678Z https://example.com",
		Fields:    map[string]string{"command": "curl -d dni=12345678Z https://example.com"},
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("got decision kind %v, want Rewrite", decision.Kind)
	}
	got := decision.RedactedFields["command"]
	if strings.Contains(got, "12345678Z") {
		t.Fatalf("RedactedFields[command] %q still contains the original DNI", got)
	}
	if !strings.Contains(got, "[DNI-001]") {
		t.Fatalf("RedactedFields[command] %q does not contain the pseudonym token", got)
	}
}

// 2. A valid DNI in a typed prompt is detected on the Claude Code path.
// Claude Code's UserPromptSubmit hook can actually enforce a rewrite here,
// so the policy substitutes a pseudonym token rather than erroring out.
func TestLeak_DNIInPrompt_OnClaudeCode_IsRewritten(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "session-1",
		Text:      "my DNI is 12345678Z, please remember it",
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("got decision kind %v, want Rewrite", decision.Kind)
	}
	if strings.Contains(decision.RedactedText, "12345678Z") {
		t.Fatalf("RedactedText %q still contains the original DNI", decision.RedactedText)
	}
}

// 3. THE MOST IMPORTANT TEST IN THE REPO.
//
// Claude Code's PostToolUse hook is observe-only: it has no way to redact
// or block a tool's output after the tool has already run. If veil ever
// evaluated a ToolOutput event for Claude Code, it must NOT be silently
// allowed through. Pretending otherwise would be worse than doing
// nothing: it would tell the caller "you are protected" when they are
// not. Evaluate must refuse to answer with a loud, explicit capability
// error instead.
//
// (This test's premise changed from an earlier version of this suite,
// which asserted OpenCode had no prompt-level hook at all. That
// assumption was never verified against a real OpenCode install and
// turned out to be wrong: OpenCode's chat.message hook can both block
// (by throwing) and rewrite (by mutating a part's text) the user's typed
// prompt, confirmed against OpenCode 1.18.32 with a local mock provider.
// See TestLeak_DNIInPrompt_OnOpenCode_IsRewritten below, and this
// project's T1 spike notes in tecnisan-harness's
// odd/tasks/poc-lunes.md, for the evidence. Claude Code's inability to
// redact a tool's OUTPUT, by contrast, is real and unchanged, so it is
// the new anchor for "the guarantee itself is what is unsupported".)
func TestLeak_ToolOutput_OnClaudeCode_IsNeverSilentlyAllowed(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind:     domain.EventToolOutput,
		Host:     domain.HostClaudeCode,
		ToolName: "Bash",
		Text:     "my DNI is 12345678Z, in the tool's output",
		Fields:   map[string]string{"output": "my DNI is 12345678Z, in the tool's output"},
	}

	decision, err := policy.Evaluate(event)
	if err == nil {
		t.Fatalf("Evaluate returned no error; got decision %+v, want an UnsupportedCapabilityError", decision)
	}

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("Evaluate returned error %v (%T), want *domain.UnsupportedCapabilityError", err, err)
	}
	if capErr.Host != domain.HostClaudeCode {
		t.Fatalf("capability error host = %q, want %q", capErr.Host, domain.HostClaudeCode)
	}
	if capErr.Capability != domain.CapabilityToolOutputRedact {
		t.Fatalf("capability error capability = %q, want %q", capErr.Capability, domain.CapabilityToolOutputRedact)
	}

	// Decision must be the zero value: never a disguised Allow.
	if decision.Kind == domain.Allow {
		t.Fatalf("decision must not be Allow when the host cannot enforce the guarantee")
	}
	if decision.Kind != domain.Unknown {
		t.Fatalf("decision.Kind = %v, want Unknown", decision.Kind)
	}
}

// 3b. The corrected companion to the old test 3: the exact same
// prompt-level DNI leak, evaluated for OpenCode, is now rewritten rather
// than erroring, because OpenCode's chat.message hook genuinely can
// enforce this (see the comment on the test above).
func TestLeak_DNIInPrompt_OnOpenCode_IsRewritten(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostOpenCode,
		SessionID: "session-1",
		Text:      "my DNI is 12345678Z, please remember it",
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("got decision kind %v, want Rewrite", decision.Kind)
	}
	if strings.Contains(decision.RedactedText, "12345678Z") {
		t.Fatalf("RedactedText %q still contains the original DNI", decision.RedactedText)
	}
}

// 4. Reading a .env file is denied on both hosts, using each host's native
// field shape (Claude Code: tool_name "Read" / tool_input.file_path;
// OpenCode: tool "read" / args.filePath).
func TestLeak_ReadingEnvFile_IsDenied_OnBothHosts(t *testing.T) {
	policy := newPolicy()

	claudeEvent := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostClaudeCode,
		ToolName: "Read",
		Text:     "file_path: /home/user/project/.env",
		Fields:   map[string]string{"file_path": "/home/user/project/.env"},
	}
	decision, err := policy.Evaluate(claudeEvent)
	if err != nil {
		t.Fatalf("Claude Code: Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("Claude Code: got decision kind %v, want Deny", decision.Kind)
	}

	openCodeEvent := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostOpenCode,
		ToolName: "read",
		Text:     "filePath: /home/user/project/.env",
		Fields:   map[string]string{"filePath": "/home/user/project/.env"},
	}
	decision, err = policy.Evaluate(openCodeEvent)
	if err != nil {
		t.Fatalf("OpenCode: Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("OpenCode: got decision kind %v, want Deny", decision.Kind)
	}
}

// 5. Negative control: a string that merely looks like a DNI, with the
// wrong check letter, must not fire, and an otherwise clean tool call must
// be Allowed. A detector that fires on everything is as useless as one
// that never fires.
func TestLeak_LookalikeDNI_And_CleanCall_AreAllowed(t *testing.T) {
	policy := newPolicy()

	lookalike := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostClaudeCode,
		ToolName: "Bash",
		Text:     "command: echo 12345678A",
		Fields:   map[string]string{"command": "echo 12345678A"},
	}
	decision, err := policy.Evaluate(lookalike)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Allow {
		t.Fatalf("lookalike DNI with wrong check letter: got decision kind %v, want Allow", decision.Kind)
	}

	clean := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostOpenCode,
		ToolName: "read",
		Text:     "filePath: /home/user/project/README.md",
		Fields:   map[string]string{"filePath": "/home/user/project/README.md"},
	}
	decision, err = policy.Evaluate(clean)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Allow {
		t.Fatalf("clean tool call: got decision kind %v, want Allow", decision.Kind)
	}
}
