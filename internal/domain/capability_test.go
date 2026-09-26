package domain_test

import (
	"errors"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestCapabilityMatrix_MatchesVerifiedHostBehavior asserts the exact,
// verified asymmetry between the two hosts. These facts come from how each
// host's hook/plugin API actually works, not from wishful thinking:
//
//   - Claude Code's UserPromptSubmit hook can block or rewrite the typed
//     prompt before the model sees it.
//   - OpenCode's chat.message hook can ALSO block (by throwing, which
//     aborts the whole request before the model is ever contacted) or
//     rewrite (by mutating a part's text) the typed prompt: verified with
//     a local mock OpenAI-compatible provider against OpenCode 1.18.32 (see
//     the project's T1 spike). This corrects an earlier, unverified
//     assumption that OpenCode had no prompt-level hook at all.
//   - Both hosts can block or rewrite tool call arguments before execution.
//   - Claude Code's PostToolUse hook is observe-only: it cannot redact a
//     tool's output. OpenCode's tool.execute.after CAN redact a tool's
//     output, but only by mutating output.output (and output.metadata.output
//     when present); throwing there does NOT block anything (also verified
//     in the T1 spike: the thrown error text just becomes the tool's own
//     result and the conversation continues).
//   - OpenCode alone exposes experimental.chat.messages.transform (rewrite
//     any text or tool-result part resent to the model from prior turns)
//     and experimental.chat.system.transform (rewrite the system prompt).
//     Claude Code has no equivalent hook for either.
func TestCapabilityMatrix_MatchesVerifiedHostBehavior(t *testing.T) {
	tests := []struct {
		name       string
		host       domain.Host
		capability domain.Capability
		want       bool
	}{
		{"claude code supports prompt blocking", domain.HostClaudeCode, domain.CapabilityPromptBlock, true},
		{"claude code supports tool args blocking", domain.HostClaudeCode, domain.CapabilityToolArgsBlock, true},
		{"claude code does not support tool output redaction", domain.HostClaudeCode, domain.CapabilityToolOutputRedact, false},
		{"claude code does not support history rewrite", domain.HostClaudeCode, domain.CapabilityHistoryRewrite, false},
		{"claude code does not support system prompt rewrite", domain.HostClaudeCode, domain.CapabilitySystemPromptRewrite, false},
		{"opencode supports prompt blocking (via chat.message)", domain.HostOpenCode, domain.CapabilityPromptBlock, true},
		{"opencode supports tool args blocking", domain.HostOpenCode, domain.CapabilityToolArgsBlock, true},
		{"opencode supports tool output redaction (via mutation, not throw)", domain.HostOpenCode, domain.CapabilityToolOutputRedact, true},
		{"opencode supports history rewrite", domain.HostOpenCode, domain.CapabilityHistoryRewrite, true},
		{"opencode supports system prompt rewrite", domain.HostOpenCode, domain.CapabilitySystemPromptRewrite, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.Supports(tt.host, tt.capability)
			if got != tt.want {
				t.Fatalf("Supports(%q, %q) = %v, want %v", tt.host, tt.capability, got, tt.want)
			}
		})
	}
}

func TestRequireCapability_Supported_ReturnsNil(t *testing.T) {
	if err := domain.RequireCapability(domain.HostClaudeCode, domain.CapabilityPromptBlock); err != nil {
		t.Fatalf("RequireCapability returned unexpected error: %v", err)
	}
}

// TestRequireCapability_Unsupported_ErrorsLoudly is the codified version of
// this project's core rule: asking for a guarantee a host cannot provide
// must produce an explicit, typed error, never a silent "allowed". Claude
// Code's PostToolUse is still observe-only, so tool output redaction is
// still the right unsupported case to exercise this with.
func TestRequireCapability_Unsupported_ErrorsLoudly(t *testing.T) {
	err := domain.RequireCapability(domain.HostClaudeCode, domain.CapabilityToolOutputRedact)
	if err == nil {
		t.Fatal("RequireCapability returned nil, want an UnsupportedCapabilityError")
	}

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error = %v (%T), want *domain.UnsupportedCapabilityError", err, err)
	}
	if capErr.Host != domain.HostClaudeCode {
		t.Errorf("capErr.Host = %q, want %q", capErr.Host, domain.HostClaudeCode)
	}
	if capErr.Capability != domain.CapabilityToolOutputRedact {
		t.Errorf("capErr.Capability = %q, want %q", capErr.Capability, domain.CapabilityToolOutputRedact)
	}
	if capErr.Error() == "" {
		t.Error("capErr.Error() must not be empty")
	}
}

func TestSupports_UnknownHost_ReturnsFalse(t *testing.T) {
	if domain.Supports(domain.Host("unknown-host"), domain.CapabilityToolArgsBlock) {
		t.Fatal("Supports returned true for an unknown host, want false")
	}
}
