package domain

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// base64RunPattern matches a long contiguous run of base64-alphabet
// characters: the shape a base64-encoded file dump takes when an MCP
// tool returns raw file bytes as text. 128 characters is short enough to
// catch a small embedded image or document while staying well above the
// length of an ordinary token, hash, or identifier that might otherwise
// appear in legitimate tool output.
var base64RunPattern = regexp.MustCompile(`[A-Za-z0-9+/]{128,}={0,2}`)

// BinaryContentDetector flags tool output veil cannot safely scan for
// personal data: invalid UTF-8 (raw binary bytes), or a long base64
// blob (the shape a base64-encoded attachment takes, which is valid
// UTF-8 but not human-readable text a regex-based detector can inspect).
// It only ever applies to EventToolOutput, and every finding it produces
// has an empty Category: there is no safe rewrite for content that
// cannot be inspected, only a block.
type BinaryContentDetector struct{}

// NewBinaryContentDetector builds a BinaryContentDetector.
func NewBinaryContentDetector() *BinaryContentDetector { return &BinaryContentDetector{} }

// Name identifies this detector.
func (d *BinaryContentDetector) Name() string { return "binary-content" }

// Detect inspects a ToolOutput event's Fields for unscannable content.
func (d *BinaryContentDetector) Detect(event Event) []Finding {
	if event.Kind != EventToolOutput {
		return nil
	}

	var findings []Finding
	for field, value := range event.Fields {
		if !utf8.ValidString(value) {
			findings = append(findings, Finding{
				Detector: "binary-content",
				Reason:   fmt.Sprintf("tool output field %q is not valid text (binary content) and cannot be scanned for personal data", field),
			})
			continue
		}
		if base64RunPattern.MatchString(value) {
			findings = append(findings, Finding{
				Detector: "binary-content",
				Reason:   fmt.Sprintf("tool output field %q looks like base64-encoded binary content and cannot be scanned for personal data", field),
			})
		}
	}
	return findings
}
