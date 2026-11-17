// Package ner is veil's adapter to a local named-entity recognition
// model that runs in its own process (a "sidecar"), behind the
// domain.FallibleDetector port.
//
// veil is one short-lived process per hook event, while a model takes
// seconds to load, so the sidecar is a long-running local service that
// veil dials per event on a Unix domain socket. The wire format is
// JSON-RPC 2.0, one message per line (newline-delimited JSON, as MCP's
// stdio transport frames it). Every exchange is one connection:
//
//	-> {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1"}}
//	<- {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1","model":{"id":..,"revision":..,"entryDigest":..}}}
//	-> {"jsonrpc":"2.0","id":2,"method":"recognize","params":{"units":["..."]}}
//	<- {"jsonrpc":"2.0","id":2,"result":{"spans":[[{"start":0,"end":8,"label":"person"}]]}}
//
// Span offsets are UTF-8 byte offsets into their unit; at most
// MaxSpansPerUnit per unit, and overlapping or touching spans become one
// finding. Each answer is the first line after its request: a line the
// sidecar sends early fails the id check of the request it is read for,
// and anything after the recognize answer is never read, since veil
// closes the connection. veil connects only to a socket that is its own
// user's and writable by no one else, in a directory that is too
// (ErrUnavailable otherwise). The timeout covers the whole call, from
// dialing to the last finding built. Anything other
// than a well-formed answer for the expected model before the deadline
// is an error, and veil fails the event closed on it (HCS-0008-R020):
// the sidecar is never optional once the policy enables it.
package ner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/FullFran/veil/internal/domain"
)

// ProtocolVersion is the sidecar protocol version this client speaks.
const ProtocolVersion = "1"

// MaxSpansPerUnit bounds the spans a sidecar may return for one unit;
// more is a protocol error. A real model finds a handful per text.
const MaxSpansPerUnit = 1024

// DefaultTimeout bounds one exchange (dial, initialize and recognize):
// about 11 times the measured GLiNER2-PII p95 per event (176 ms,
// research/ner-benchmark), and far below a host's own hook deadline.
const DefaultTimeout = 2 * time.Second

// Environment variables that configure the client.
const (
	// SocketEnvVar overrides the sidecar's socket path.
	SocketEnvVar = "VEIL_NER_SOCKET"
	// ModelEnvVar selects the model when the policy enables ner without
	// one.
	ModelEnvVar = "VEIL_NER_MODEL"
)

// SocketPath returns $VEIL_NER_SOCKET, else $XDG_RUNTIME_DIR/veil/ner.sock
// (a per-user directory only its owner can enter), else "": with no path
// the detector reports ErrUnavailable rather than guess a shared one.
func SocketPath() string {
	if s := os.Getenv(SocketEnvVar); s != "" {
		return s
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "veil", "ner.sock")
	}
	return ""
}

// DetectorName is the detector id of NER findings, in Finding.Detector,
// the policy and evidence.
const DetectorName = "ner"

// Failure classes. Every error Detect returns wraps exactly one of them;
// callers branch with errors.Is, never on the message.
var (
	// ErrUnavailable: no sidecar listens on the socket, or the socket or
	// its directory is not private to veil's user.
	ErrUnavailable = errors.New("ner: sidecar unavailable")
	// ErrTimeout: the exchange did not finish before the deadline.
	ErrTimeout = errors.New("ner: sidecar timed out")
	// ErrCrashed: the sidecar closed the connection mid-exchange.
	ErrCrashed = errors.New("ner: sidecar closed the connection")
	// ErrProtocol: the sidecar answered something that is not a valid
	// answer: bad JSON, an error reply, another protocol version, the
	// wrong number of span lists, a span outside its unit or off a rune
	// boundary, or a label veil did not ask for.
	ErrProtocol = errors.New("ner: sidecar protocol error")
	// ErrModelMismatch: the sidecar serves a model other than the one
	// the policy selected (another id, revision or catalog entry).
	ErrModelMismatch = errors.New("ner: sidecar serves another model")
)

// Model identifies the model the sidecar must be serving: a catalog
// entry id, its pinned revision and the digest of the entry itself.
type Model struct {
	ID          string `json:"id"`
	Revision    string `json:"revision"`
	EntryDigest string `json:"entryDigest"`
}

// Config is everything the detector needs to reach its sidecar.
type Config struct {
	// Socket is the Unix domain socket path the sidecar listens on.
	Socket string
	// Timeout bounds one exchange; zero means DefaultTimeout.
	Timeout time.Duration
	// Model is what the sidecar must report in its initialize answer.
	Model Model
	// Labels maps each model label veil accepts to its finding category
	// (e.g. "person" -> "NOMBRE"). A span with any other label is a
	// protocol error.
	Labels map[string]string
}

// Detector is a domain.FallibleDetector backed by a sidecar.
type Detector struct {
	cfg Config
}

var _ domain.FallibleDetector = (*Detector)(nil)

// NewDetector builds a detector for cfg.
func NewDetector(cfg Config) *Detector {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Detector{cfg: cfg}
}

// Name returns DetectorName.
func (d *Detector) Name() string { return DetectorName }

// Detect asks the sidecar for entities in event and returns one finding
// per span, or an error wrapping one of the failure classes. An event
// with nothing to scan never dials the sidecar.
func (d *Detector) Detect(event domain.Event) ([]domain.Finding, error) {
	units := unitsOf(event)
	if len(units) == 0 {
		return nil, nil
	}
	deadline := time.Now().Add(d.cfg.Timeout)
	spans, err := d.exchange(deadline, units)
	if err != nil {
		return nil, err
	}
	var findings []domain.Finding
	for i, unit := range units {
		for _, sp := range spans[i] {
			findings = append(findings, domain.Finding{
				Detector: DetectorName,
				Reason:   "model name detected",
				Redacted: "[" + d.cfg.Labels[sp.Label] + "]",
				Match:    unit[sp.Start:sp.End],
				Category: d.cfg.Labels[sp.Label],
			})
		}
	}
	// The timeout covers the whole call, building findings included.
	if time.Now().After(deadline) {
		return nil, fmt.Errorf("%w: answer not processed before the deadline", ErrTimeout)
	}
	return findings, nil
}

// unitsOf returns the texts to send: the non-empty values of a tool
// call's fields, ordered by key, or else the event's text. Hosts build
// Text from Fields, so the fields are the same content in the shape the
// model reads best (research/ner-benchmark scored them the same way).
func unitsOf(event domain.Event) []string {
	if len(event.Fields) > 0 {
		keys := make([]string, 0, len(event.Fields))
		for k, v := range event.Fields {
			if v != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		units := make([]string, 0, len(keys))
		for _, k := range keys {
			units = append(units, event.Fields[k])
		}
		return units
	}
	if event.Text == "" {
		return nil
	}
	return []string{event.Text}
}
