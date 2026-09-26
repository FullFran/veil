package domain

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

// Registry holds an ordered set of Detectors to run against an Event.
type Registry struct {
	detectors []Detector
}

// NewRegistry builds a Registry that runs the given detectors, in order.
func NewRegistry(detectors ...Detector) *Registry {
	return &Registry{detectors: detectors}
}

// Register appends a detector to the registry.
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// DetectAll runs every registered detector against event and concatenates
// their findings, preserving registration order.
func (r *Registry) DetectAll(event Event) []Finding {
	var findings []Finding
	for _, d := range r.detectors {
		findings = append(findings, d.Detect(event)...)
	}
	return findings
}
