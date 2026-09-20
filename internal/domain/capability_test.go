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
//   - OpenCode exposes no hook that reaches the typed prompt at all.
//   - Both hosts can block or rewrite tool call arguments before execution.
//   - Claude Code's PostToolUse hook is observe-only: it cannot redact a
//     tool's output. OpenCode's tool.execute.after is unverified and is
//     therefore also treated as unsupported.
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
		{"opencode does not support prompt blocking", domain.HostOpenCode, domain.CapabilityPromptBlock, false},
		{"opencode supports tool args blocking", domain.HostOpenCode, domain.CapabilityToolArgsBlock, true},
		{"opencode does not support tool output redaction", domain.HostOpenCode, domain.CapabilityToolOutputRedact, false},
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
// must produce an explicit, typed error, never a silent "allowed".
func TestRequireCapability_Unsupported_ErrorsLoudly(t *testing.T) {
	err := domain.RequireCapability(domain.HostOpenCode, domain.CapabilityPromptBlock)
	if err == nil {
		t.Fatal("RequireCapability returned nil, want an UnsupportedCapabilityError")
	}

	var capErr *domain.UnsupportedCapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error = %v (%T), want *domain.UnsupportedCapabilityError", err, err)
	}
	if capErr.Host != domain.HostOpenCode {
		t.Errorf("capErr.Host = %q, want %q", capErr.Host, domain.HostOpenCode)
	}
	if capErr.Capability != domain.CapabilityPromptBlock {
		t.Errorf("capErr.Capability = %q, want %q", capErr.Capability, domain.CapabilityPromptBlock)
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
