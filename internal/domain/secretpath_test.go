package domain_test

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

func TestSecretPathDetector_EnvFile_ClaudeCodeFieldName_Fires(t *testing.T) {
	detector := domain.NewSecretPathDetector()
	event := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostClaudeCode,
		ToolName: "Read",
		Fields:   map[string]string{"file_path": "/home/user/project/.env"},
	}

	findings := detector.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (findings: %+v)", len(findings), findings)
	}
	if findings[0].Detector != "secret-path" {
		t.Errorf("Detector = %q, want %q", findings[0].Detector, "secret-path")
	}
}

func TestSecretPathDetector_EnvFile_OpenCodeFieldName_Fires(t *testing.T) {
	detector := domain.NewSecretPathDetector()
	event := domain.Event{
		Kind:     domain.EventToolArgs,
		Host:     domain.HostOpenCode,
		ToolName: "read",
		Fields:   map[string]string{"filePath": "/home/user/project/.env"},
	}

	findings := detector.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (findings: %+v)", len(findings), findings)
	}
}

func TestSecretPathDetector_SSHPrivateKey_Fires(t *testing.T) {
	detector := domain.NewSecretPathDetector()
	event := domain.Event{
		Kind:   domain.EventToolArgs,
		Host:   domain.HostClaudeCode,
		Fields: map[string]string{"file_path": "/home/user/.ssh/id_rsa"},
	}

	findings := detector.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (findings: %+v)", len(findings), findings)
	}
}

func TestSecretPathDetector_OrdinaryFile_DoesNotFire(t *testing.T) {
	detector := domain.NewSecretPathDetector()
	event := domain.Event{
		Kind:   domain.EventToolArgs,
		Host:   domain.HostClaudeCode,
		Fields: map[string]string{"file_path": "/home/user/project/README.md"},
	}

	findings := detector.Detect(event)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (findings: %+v)", len(findings), findings)
	}
}

func TestSecretPathDetector_PromptSubmitEvent_NeverFires(t *testing.T) {
	// A path-like substring in a plain typed prompt is not a tool call
	// targeting a file; this detector must stay scoped to ToolArgs
	// events only.
	detector := domain.NewSecretPathDetector()
	event := domain.Event{
		Kind: domain.EventPromptSubmit,
		Host: domain.HostClaudeCode,
		Text: "please read my .env file for me",
	}

	findings := detector.Detect(event)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (findings: %+v)", len(findings), findings)
	}
}

func TestSecretPathDetector_Name(t *testing.T) {
	if got := domain.NewSecretPathDetector().Name(); got != "secret-path" {
		t.Fatalf("Name() = %q, want %q", got, "secret-path")
	}
}
