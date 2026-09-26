package domain_test

import (
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestBinaryContentDetector_InvalidUTF8_IsHardDenied proves invalid UTF-8
// (raw binary bytes, e.g. an MCP tool returning file bytes) in a tool
// output field forces a hard deny: veil cannot scan what it cannot decode
// as text, so it must fail closed rather than pass it through unscanned.
func TestBinaryContentDetector_InvalidUTF8_IsHardDenied(t *testing.T) {
	d := domain.NewBinaryContentDetector()
	event := domain.Event{
		Kind:   domain.EventToolOutput,
		Fields: map[string]string{"output": string([]byte{0xff, 0xfe, 0x00, 0x01, 0x02})},
	}

	findings := d.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Category != "" {
		t.Fatalf("Category = %q, want empty (this must always Deny, never Rewrite)", findings[0].Category)
	}
}

// TestBinaryContentDetector_LongBase64Blob_IsHardDenied proves a long run
// of base64-alphabet characters (the shape a base64-encoded file dump
// takes) is treated the same way, even though it is technically valid
// UTF-8 text.
func TestBinaryContentDetector_LongBase64Blob_IsHardDenied(t *testing.T) {
	d := domain.NewBinaryContentDetector()
	blob := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", 4) // 200 chars, base64 alphabet only
	event := domain.Event{
		Kind:   domain.EventToolOutput,
		Fields: map[string]string{"output": blob},
	}

	findings := d.Detect(event)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Category != "" {
		t.Fatalf("Category = %q, want empty (this must always Deny, never Rewrite)", findings[0].Category)
	}
}

// TestBinaryContentDetector_OrdinaryText_IsIgnored is the negative
// control, and proves the detector never fires outside EventToolOutput.
func TestBinaryContentDetector_OrdinaryText_IsIgnored(t *testing.T) {
	d := domain.NewBinaryContentDetector()

	ordinary := domain.Event{Kind: domain.EventToolOutput, Fields: map[string]string{"output": "hi\n"}}
	if findings := d.Detect(ordinary); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}

	wrongKind := domain.Event{Kind: domain.EventToolArgs, Fields: map[string]string{"output": string([]byte{0xff, 0xfe})}}
	if findings := d.Detect(wrongKind); len(findings) != 0 {
		t.Fatalf("got %d findings for a non-ToolOutput event, want 0: %+v", len(findings), findings)
	}
}
