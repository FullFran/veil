package domain

import "fmt"

// Finding is a single piece of evidence a Detector found in an Event.
type Finding struct {
	// Detector is the name of the detector that produced this finding,
	// used in logs and combined deny reasons.
	Detector string
	// Reason is a human-readable explanation of what was found.
	Reason string
	// Redacted is a masked replacement for the sensitive value, for use
	// in a Deny reason or log line. It is never sent to the model as
	// itself; Policy substitutes a stable pseudonym token instead.
	Redacted string
	// Match is the exact original substring this finding matched in the
	// event's text. Policy uses it, verbatim, to find-and-replace every
	// occurrence with a stable pseudonym token. Empty for a finding that
	// does not target a specific substring (e.g. a whole-field secret
	// path finding).
	Match string
	// Category is the pseudonym token prefix (e.g. "DNI", "IBAN",
	// "EMAIL", "TEL", "NOMBRE") for a finding Policy may Rewrite instead
	// of Deny. Empty means this finding must never be rewritten and
	// always forces a Deny: veil has no way to make the payload safe
	// short of blocking it outright (e.g. a tool call targeting a
	// secrets-bearing file).
	Category string
	// Key is the canonical value Policy mints the pseudonym for (e.g. the
	// compact "12345678Z" for a written "12.345.678-Z"), so one value
	// written two ways is one token, and rehydration gives back Key.
	// Empty means Match itself.
	Key string
}

// Detector inspects an Event and reports any Findings. Implementations
// must not depend on which host produced the Event.
type Detector interface {
	// Name identifies the detector, used in Finding.Detector and logs.
	Name() string
	// Detect inspects event and returns any findings. A nil or empty
	// slice means nothing suspicious was found.
	Detect(event Event) []Finding
}

// FallibleDetector is the port for a detector that can fail to answer,
// such as one backed by a local model in another process. A failure is
// never "nothing found": Registry and Policy fail the whole event closed
// on it (HCS-0008-R020). Implementations must not depend on which host
// produced the Event, and must return either findings or an error.
type FallibleDetector interface {
	// Name identifies the detector, used in Finding.Detector and logs.
	Name() string
	// Detect inspects event and returns any findings, or an error when
	// it could not inspect it.
	Detect(event Event) ([]Finding, error)
}

// infallible adapts a Detector to FallibleDetector.
type infallible struct{ detector Detector }

func (d infallible) Name() string { return d.detector.Name() }

func (d infallible) Detect(event Event) ([]Finding, error) { return d.detector.Detect(event), nil }

// Registry holds an ordered set of detectors to run against an Event.
type Registry struct {
	detectors []FallibleDetector
}

// NewRegistry builds a Registry that runs the given detectors, in order.
func NewRegistry(detectors ...Detector) *Registry {
	r := &Registry{}
	for _, d := range detectors {
		r.Register(d)
	}
	return r
}

// Register appends a detector to the registry.
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, infallible{d})
}

// RegisterFallible appends a detector that can fail to the registry.
func (r *Registry) RegisterFallible(d FallibleDetector) {
	r.detectors = append(r.detectors, d)
}

// Detectors returns the registered detectors, in registration order.
func (r *Registry) Detectors() []FallibleDetector {
	return append([]FallibleDetector(nil), r.detectors...)
}

// DetectAll runs every registered detector against event and concatenates
// their findings, preserving registration order. When event.Text holds
// Unicode lookalike forms (full-width characters, format characters,
// digits of another script), the detectors run once more on its
// normalized view and the extra findings follow, each keyed by the
// canonical value and matching the original written span (lookalike.go).
// Any detector error, on either pass, is returned with no findings: the
// caller must fail closed, never treat it as a clean event.
func (r *Registry) DetectAll(event Event) ([]Finding, error) {
	findings, err := r.detectRaw(event)
	if err != nil {
		return nil, err
	}
	extra, err := lookalikeFindings(event, findings, r.detectRaw)
	if err != nil {
		return nil, err
	}
	return append(findings, extra...), nil
}

func (r *Registry) detectRaw(event Event) ([]Finding, error) {
	var findings []Finding
	for _, d := range r.detectors {
		found, err := d.Detect(event)
		if err != nil {
			return nil, fmt.Errorf("veil: detector %s: %w", d.Name(), err)
		}
		findings = append(findings, found...)
	}
	return findings, nil
}
