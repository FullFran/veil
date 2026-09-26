package domain

import "regexp"

// emailPattern matches an ordinary email address. It deliberately does not
// exclude RFC 2606 example domains the way HagaHarness's sensitive-scan.mjs
// does: veil scans live agent traffic, not documentation, so a
// "user@example.com" in a real prompt is still worth rewriting rather than
// silently ignoring.
var emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

// EmailDetector finds email addresses.
type EmailDetector struct{}

// NewEmailDetector builds an EmailDetector.
func NewEmailDetector() *EmailDetector { return &EmailDetector{} }

// Name identifies this detector.
func (d *EmailDetector) Name() string { return "email" }

// Detect scans event.Text for email addresses.
func (d *EmailDetector) Detect(event Event) []Finding {
	var findings []Finding
	for _, m := range emailPattern.FindAllString(event.Text, -1) {
		findings = append(findings, Finding{
			Detector: "email",
			Reason:   "email address detected",
			Redacted: "***@***",
			Match:    m,
			Category: "EMAIL",
		})
	}
	return findings
}
