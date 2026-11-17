// Package problem defines how veil reports a failure: one RFC 9457
// problem details object, written as a single JSON line on stderr.
//
// veil is not an HTTP API, so this is a non-HTTP profile of RFC 9457
// (Appendix C allows other carriers): the object has type, title, detail
// and the extension member code, and never status, which is an HTTP
// status code. Consumers branch on type (or its mirror code), never on
// title or detail.
//
// Every code veil raises, on the binary or the OpenCode plugin side, is
// defined here so later changes reuse them instead of minting new ones.
// A code and its type are stable once released: renaming one breaks
// every host that branches on it.
package problem

import (
	"encoding/json"
	"io"
	"strings"
)

// Code is a stable, machine-readable failure identifier. It mirrors the
// problem type for hosts that prefer a token over a URI.
type Code string

const (
	// Usage: bad command-line arguments.
	Usage Code = "VEIL_USAGE"
	// InputInvalid: stdin is not exactly one valid event for the host.
	InputInvalid Code = "VEIL_INPUT_INVALID"
	// CatalogUnreadable: the name catalog (VEIL_CATALOG or the policy's
	// catalog.path) cannot be read or parsed.
	CatalogUnreadable Code = "VEIL_CATALOG_UNREADABLE"
	// PolicyUnreadable: VEIL_POLICY is set but the file cannot be read.
	PolicyUnreadable Code = "VEIL_POLICY_UNREADABLE"
	// PolicyInvalid: the policy is not one JSON document, does not
	// validate against the policy schema, or is ambiguous (for example
	// VEIL_CATALOG and the policy's catalog.path are both set).
	PolicyInvalid Code = "VEIL_POLICY_INVALID"
	// CapabilityUnsupported: the host cannot enforce the decision veil
	// would have to make (for example tool-output redaction on Claude Code).
	CapabilityUnsupported Code = "VEIL_CAPABILITY_UNSUPPORTED"
	// StoreKeyMissing: the pseudonym store's encryption key is not set.
	StoreKeyMissing Code = "VEIL_STORE_KEY_MISSING"
	// StoreKeyInvalid: the pseudonym store's encryption key is malformed
	// or does not open the store.
	StoreKeyInvalid Code = "VEIL_STORE_KEY_INVALID"
	// StoreCorrupt: a pseudonym session file exists but cannot be parsed.
	StoreCorrupt Code = "VEIL_STORE_CORRUPT"
	// StoreKeyringUnavailable: the OS keyring holding the store key
	// cannot be reached.
	StoreKeyringUnavailable Code = "VEIL_STORE_KEYRING_UNAVAILABLE"
	// StoreLocked: the pseudonym session file stayed locked by another
	// process past the deadline.
	StoreLocked Code = "VEIL_STORE_LOCKED"
	// SessionRetired: the pseudonym session was removed when its marker
	// counters could not be read, so it can never mint again without
	// risking a repeated marker. The host must start a new session id.
	SessionRetired Code = "VEIL_SESSION_RETIRED"
	// SessionIDMissing: the event needs the pseudonym store and the host
	// sent no session id. veil never shares one mapping between events
	// that have no session.
	SessionIDMissing Code = "VEIL_SESSION_ID_MISSING"
	// StoreIO: the pseudonym store cannot be read or written.
	StoreIO Code = "VEIL_STORE_IO"
	// EvidenceWrite: the evidence sink cannot be written.
	EvidenceWrite Code = "VEIL_EVIDENCE_WRITE"
	// CatalogRevisionInvalid: VEIL_CATALOG_REVISION is set but is not an
	// opaque token ([A-Za-z0-9._:-]{1,128}).
	CatalogRevisionInvalid Code = "VEIL_CATALOG_REVISION_INVALID"
	// ACSVersionUnsupported: an ACS message declares an acs_version veil
	// has no adapter for (JSON-RPC -32001 UNSUPPORTED_VERSION).
	ACSVersionUnsupported Code = "VEIL_ACS_VERSION_UNSUPPORTED"
	// ACSRequestInvalid: an ACS message is a batch or does not validate
	// against the vendored ACS schema for its envelope or its method's
	// payload (JSON-RPC -32600 or -32602).
	ACSRequestInvalid Code = "VEIL_ACS_REQUEST_INVALID"
	// ACSMethodUnsupported: an ACS method veil does not evaluate
	// (JSON-RPC -32003 CAPABILITY_NOT_NEGOTIATED).
	ACSMethodUnsupported Code = "VEIL_ACS_METHOD_UNSUPPORTED"
	// ACSSignatureInvalid: an ACS request's signature is missing while a
	// secret is configured, names an unknown key_id or algorithm, or does
	// not verify (JSON-RPC -32004 SIGNATURE_INVALID).
	ACSSignatureInvalid Code = "VEIL_ACS_SIGNATURE_INVALID"
	// ACSReplay: an ACS request_id was already seen in the session
	// (JSON-RPC -32005 REPLAY_DETECTED).
	ACSReplay Code = "VEIL_ACS_REPLAY"
	// ACSTimestampOutOfWindow: an ACS request's timestamp is outside the
	// skew window (JSON-RPC -32006 TIMESTAMP_OUT_OF_WINDOW).
	ACSTimestampOutOfWindow Code = "VEIL_ACS_TIMESTAMP_OUT_OF_WINDOW"
	// ACSKeyInvalid: the ACS HMAC secret configuration is incomplete,
	// unreadable or too short.
	ACSKeyInvalid Code = "VEIL_ACS_KEY_INVALID"
	// ACSUnredactable: an ACS step carries data veil would pseudonymize
	// where no ACS modification can be trusted to replace it (a member
	// name, metadata, the tool name, raw_command), so veil denies it.
	ACSUnredactable Code = "VEIL_ACS_UNREDACTABLE"
	// Timeout: raised by the OpenCode plugin when the binary does not
	// answer in time.
	Timeout Code = "VEIL_TIMEOUT"
	// OutputTooLarge: raised by the OpenCode plugin when the binary's
	// answer exceeds its buffer.
	OutputTooLarge Code = "VEIL_OUTPUT_TOO_LARGE"
	// Unavailable: raised by the OpenCode plugin when the binary cannot be
	// run or its answer cannot be understood.
	Unavailable Code = "VEIL_UNAVAILABLE"
	// Internal: a failure no other code classifies. It still fails closed.
	Internal Code = "VEIL_INTERNAL"
)

// TypeBase prefixes every problem type URI. It is an RFC 4151 tag URI:
// veil owns no DNS domain, and a tag URI is globally unique without one
// as long as its authority (the GitHub Pages host of the project owner)
// was assigned to the minter on its date. Type URIs are identifiers and
// are not meant to be dereferenced.
const TypeBase = "tag:fullfran.github.io,2026:veil/problems/"

// Exit classes. The exit code carries only the class; the detail is in
// the problem object. A host adapter may map ExitFailedClosed to the code
// its host requires to block (see internal/hosts).
const (
	// ExitDecision: veil made a decision (allow, deny or rewrite).
	ExitDecision = 0
	// ExitFailedClosed: veil failed; the event must not proceed.
	ExitFailedClosed = 1
	// ExitUsage: veil was invoked with bad arguments.
	ExitUsage = 2
)

// titles holds the fixed, human-readable summary of each code. Titles
// and details are fixed text: they never interpolate input, an
// underlying error, a path or a session id, so a problem can never carry
// a detected value.
var titles = map[Code]string{
	Usage:                   "Invalid command-line usage",
	InputInvalid:            "Input is not one valid event",
	CatalogUnreadable:       "Name catalog cannot be loaded",
	PolicyUnreadable:        "Policy file cannot be read",
	PolicyInvalid:           "Policy is invalid",
	CapabilityUnsupported:   "Host cannot enforce the decision",
	StoreKeyMissing:         "Pseudonym store key is missing",
	StoreKeyInvalid:         "Pseudonym store key is invalid",
	StoreCorrupt:            "Pseudonym store is corrupt",
	StoreKeyringUnavailable: "Keyring is unavailable",
	StoreLocked:             "Pseudonym store is locked",
	SessionRetired:          "Pseudonym session is retired",
	SessionIDMissing:        "Session id is missing",
	StoreIO:                 "Pseudonym store cannot be read or written",
	EvidenceWrite:           "Evidence cannot be written",
	CatalogRevisionInvalid:  "Catalog revision is invalid",
	ACSVersionUnsupported:   "ACS version is not supported",
	ACSRequestInvalid:       "ACS request is invalid",
	ACSMethodUnsupported:    "ACS method is not evaluated",
	ACSSignatureInvalid:     "ACS signature is invalid",
	ACSReplay:               "ACS request was replayed",
	ACSTimestampOutOfWindow: "ACS timestamp is out of window",
	ACSKeyInvalid:           "ACS secret is invalid",
	ACSUnredactable:         "ACS step carries data veil cannot redact",
	Timeout:                 "veil did not answer in time",
	OutputTooLarge:          "veil answer is too large",
	Unavailable:             "veil is unavailable",
	Internal:                "Internal failure",
}

var details = map[Code]string{
	Usage:                   "Run veil with exactly one host argument (claude-code, opencode or acs), or as veil policy [file] or veil store <command>.",
	InputInvalid:            "stdin must hold exactly one JSON event of a kind the host adapter supports.",
	CatalogUnreadable:       "The name catalog (VEIL_CATALOG or the policy's catalog.path) cannot be read or parsed.",
	PolicyUnreadable:        "VEIL_POLICY is set but the file cannot be read.",
	PolicyInvalid:           "The policy does not validate against the veil policy schema or is ambiguous; veil does not fall back to the default policy.",
	CapabilityUnsupported:   "This host cannot enforce a deny or rewrite for this event, so veil fails closed.",
	StoreKeyMissing:         "The pseudonym store needs an encryption key and none is configured.",
	StoreKeyInvalid:         "The configured pseudonym store key is malformed or does not open the store.",
	StoreCorrupt:            "A pseudonym session file cannot be parsed; veil refuses to start over and reuse tokens.",
	StoreKeyringUnavailable: "The OS keyring that holds the pseudonym store key cannot be reached.",
	StoreLocked:             "Another veil process held the pseudonym session lock past the deadline.",
	SessionRetired:          "This session was removed without its marker counters, so veil cannot mint for it without repeating a marker; use a new session id.",
	SessionIDMissing:        "The event needs a pseudonym but carries no session id; veil never shares one pseudonym mapping between events without a session.",
	StoreIO:                 "The pseudonym store directory or a session file cannot be read or written.",
	EvidenceWrite:           "The evidence sink cannot be written, so veil fails closed.",
	CatalogRevisionInvalid:  "VEIL_CATALOG_REVISION must be an opaque token of 1 to 128 characters from A-Z, a-z, 0-9, '.', '_', ':' and '-'.",
	ACSVersionUnsupported:   "The message's acs_version has no veil adapter; data.supported_versions lists the versions veil speaks.",
	ACSRequestInvalid:       "The message is a batch or does not validate against the vendored ACS schema for its envelope or its method's payload.",
	ACSMethodUnsupported:    "veil does not evaluate this ACS method, so it fails closed instead of allowing it.",
	ACSSignatureInvalid:     "The ACS signature is missing while a secret is configured, names an unknown key_id or algorithm, or does not verify.",
	ACSReplay:               "This request_id was already seen in the session.",
	ACSTimestampOutOfWindow: "The request timestamp is outside the skew window; data.skew_window_ms carries the window.",
	ACSKeyInvalid:           "VEIL_ACS_KEY_ID and a secret of at least 32 bytes (base64, from VEIL_ACS_KEY_FD or the veil-acs-key credential) must be set together.",
	ACSUnredactable:         "veil would pseudonymize data in a member name, metadata, the tool name or raw_command, which no ACS modification can be trusted to replace, so it denies the step.",
	Timeout:                 "The veil binary did not answer before the deadline.",
	OutputTooLarge:          "The veil binary answered with more data than the plugin accepts.",
	Unavailable:             "The veil binary cannot be run or its answer cannot be understood.",
	Internal:                "veil failed in a way no other problem type describes.",
}

// all fixes the order All returns.
var all = []Code{
	Usage, InputInvalid, CatalogUnreadable, PolicyUnreadable, PolicyInvalid, CapabilityUnsupported,
	StoreKeyMissing, StoreKeyInvalid, StoreCorrupt, StoreKeyringUnavailable, StoreLocked, SessionRetired, SessionIDMissing, StoreIO,
	EvidenceWrite, CatalogRevisionInvalid,
	ACSVersionUnsupported, ACSRequestInvalid, ACSMethodUnsupported, ACSSignatureInvalid,
	ACSReplay, ACSTimestampOutOfWindow, ACSKeyInvalid, ACSUnredactable,
	Timeout, OutputTooLarge, Unavailable,
	Internal,
}

// All returns every code veil defines.
func All() []Code {
	return append([]Code(nil), all...)
}

// Type returns the code's stable problem type URI: TypeBase followed by
// the code without its VEIL_ prefix, lowercased, with "_" as "-".
func (c Code) Type() string {
	slug := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(string(c), "VEIL_")), "_", "-")
	return TypeBase + slug
}

// Title returns the code's fixed human-readable summary.
func (c Code) Title() string {
	return titles[c]
}

// Problem is the RFC 9457 problem details object veil emits.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Code   Code   `json:"code"`
}

// New builds the problem for code.
func New(code Code) Problem {
	return Problem{Type: code.Type(), Title: code.Title(), Detail: details[code], Code: code}
}

// Write writes p to w as one JSON line.
func Write(w io.Writer, p Problem) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
