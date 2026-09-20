package domain

import (
	"path/filepath"
	"strings"
)

// sensitivePathMarkers lists substrings of file basenames that commonly
// hold secrets and must never be read (or otherwise touched) by an agent
// tool call.
var sensitivePathMarkers = []string{
	".env",
	"id_rsa",
	"id_ed25519",
	".pem",
	".pfx",
	"credentials.json",
	".npmrc",
	".netrc",
	".pgpass",
}

// SecretPathDetector flags tool calls whose arguments target a well-known
// secrets-bearing file, such as a .env file or an SSH private key. It
// looks at any Fields entry whose key name suggests a filesystem path, so
// it works across hosts regardless of each host's own field naming (e.g.
// Claude Code's "file_path" or OpenCode's "filePath").
type SecretPathDetector struct{}

// NewSecretPathDetector builds a SecretPathDetector.
func NewSecretPathDetector() *SecretPathDetector { return &SecretPathDetector{} }

// Name identifies this detector.
func (d *SecretPathDetector) Name() string { return "secret-path" }

// Detect inspects a ToolArgs event's Fields for a sensitive path. It never
// fires on any other event kind: a path-like substring appearing in a
// typed prompt is not a tool call targeting a file.
func (d *SecretPathDetector) Detect(event Event) []Finding {
	if event.Kind != EventToolArgs {
		return nil
	}

	var findings []Finding
	for field, value := range event.Fields {
		if !looksLikePathField(field) {
			continue
		}
		if !isSensitivePath(value) {
			continue
		}
		findings = append(findings, Finding{
			Detector: "secret-path",
			Reason:   "tool argument targets a known secrets-bearing file: " + value,
		})
	}
	return findings
}

// looksLikePathField reports whether field is the kind of tool argument
// key that typically carries a filesystem path.
func looksLikePathField(field string) bool {
	lower := strings.ToLower(field)
	return strings.Contains(lower, "path") || strings.Contains(lower, "file")
}

// isSensitivePath reports whether path's basename matches a known
// secrets-bearing file marker.
func isSensitivePath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, marker := range sensitivePathMarkers {
		if strings.Contains(base, marker) {
			return true
		}
	}
	return false
}
