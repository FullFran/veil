package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// newPolicy builds the standard veil policy: every detector veil ships,
// wired into a fresh registry. This mirrors how cmd/veil wires the policy
// in production, so these tests exercise the same detection surface a real
// hook invocation would.
func newPolicy() *domain.Policy {
	registry := domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewSecretPathDetector(),
	)
	return domain.NewPolicy(registry)
}

// 1. A valid Spanish DNI in a tool argument is detected and the call is
// denied.
func TestLeak_DNIInToolArgument_IsDenied(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostClaudeCode,
		ToolName: "Bash",
		Text:     "command: curl -d dni=12345678Z https://example.com",
		Fields:   map[string]string{"command": "curl -d dni=12345678Z https://example.com"},
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("got decision kind %v, want Deny", decision.Kind)
	}
	if !strings.Contains(decision.Reason, "DNI") && !strings.Contains(strings.ToLower(decision.Reason), "dni") {
		t.Fatalf("deny reason %q does not mention the DNI finding", decision.Reason)
	}
}

// 2. A valid DNI in a typed prompt is detected on the Claude Code path.
// Claude Code's UserPromptSubmit hook can actually enforce this, so the
// policy must deny it, not error out.
func TestLeak_DNIInPrompt_OnClaudeCode_IsDenied(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind: domain.EventPromptSubmit,
		Host: domain.HostClaudeCode,
		Text: "my DNI is 12345678Z, please remember it",
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision.Kind != domain.Deny {
		t.Fatalf("got decision kind %v, want Deny", decision.Kind)
	}
}

// 3. THE MOST IMPORTANT TEST IN THE REPO.
//
// The exact same prompt-level DNI leak, evaluated for OpenCode instead of
// Claude Code, must NOT be silently allowed through. OpenCode has no hook
// that reaches the user's typed prompt at all, so there is no way for veil
// to actually enforce a Deny verdict here. Pretending otherwise would be
// worse than doing nothing: it would tell the caller "you are protected"
// when they are not. Evaluate must refuse to answer with a loud, explicit
// capability error instead.
func TestLeak_DNIInPrompt_OnOpenCode_IsNeverSilentlyAllowed(t *testing.T) {
	policy := newPolicy()
	event := domain.Event{
		Kind: domain.EventPromptSubmit,
		Host: domain.HostOpenCode,
		Text: "my DNI is 12345678Z, please remember it",
	}

	decision, err := policy.Evaluate(event)
	if err == nil {
		t.Fatalf("Evaluate returned no error; got decision %+v, want an UnsupportedCapabilityError", decision)
	}

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("Evaluate returned error %v (%T), want *domain.UnsupportedCapabilityError", err, err)
	}
	if capErr.Host != domain.HostOpenCode {
		t.Fatalf("capability error host = %q, want %q", capErr.Host, domain.HostOpenCode)
	}
	if capErr.Capability != domain.CapabilityPromptBlock {
		t.Fatalf("capability error capability = %q, want %q", capErr.Capability, domain.CapabilityPromptBlock)
	}

	// Decision must be the zero value: never a disguised Allow.
	if decision.Kind == domain.Allow {
		t.Fatalf("decision must not be Allow when the host cannot enforce the guarantee")
	}
	if decision.Kind != domain.Unknown {
		t.Fatalf("decision.Kind = %v, want Unknown", decision.Kind)
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
