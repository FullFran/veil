// Command veil is the host-agnostic entrypoint invoked by a Claude Code
// hook or the OpenCode shim. It reads one JSON event on stdin, evaluates
// it against veil's privacy policy, and writes the host's expected
// response to stdout/stderr with the matching exit code. A failure is one
// RFC 9457 problem details line on stderr; the exit code carries only its
// class (see internal/problem and the README). `veil store reveal|forget
// <session>` serves a host the pseudonym store instead (see store.go), and
// `veil acs` answers OWASP Agent Control Standard messages (see acs.go).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/evidence"
	"github.com/FullFran/veil/internal/hosts/claudecode"
	"github.com/FullFran/veil/internal/hosts/opencode"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// Environment variables for decision evidence (see internal/evidence).
const (
	// evidenceFileEnv names a JSONL file every decision's evidence record
	// is appended to. Unset or empty means no file.
	evidenceFileEnv = "VEIL_EVIDENCE_FILE"
	// catalogRevisionEnv is an optional opaque revision of the name
	// catalog, supplied by the host and recorded as-is.
	catalogRevisionEnv = "VEIL_CATALOG_REVISION"
)

// engine is everything one invocation decides with: the domain policy,
// the registry it runs (to count findings for evidence) and what the
// evidence records about the configuration.
type engine struct {
	evaluator       *domain.Policy
	registry        *domain.Registry
	policyDigest    string
	policyVersion   string
	catalogRevision string
	evidenceFile    string
}

// newEngine builds the veil policy shared by every host from the policy
// file in VEIL_POLICY (or the embedded default policy when it is unset)
// and reads the evidence configuration. It returns an error instead of an
// engine if the policy file, the name catalog it uses or the catalog
// revision is invalid: startup fails closed rather than silently running
// with a different policy.
func newEngine() (*engine, error) {
	revision := os.Getenv(catalogRevisionEnv)
	if revision != "" {
		if err := evidence.ValidateRevision(revision); err != nil {
			return nil, err
		}
	}
	p, err := policy.FromEnv()
	if err != nil {
		return nil, err
	}
	registry, err := p.Registry(os.Getenv("VEIL_CATALOG"))
	if err != nil {
		return nil, err
	}
	store := newStore()
	if ttl, ok := p.Retention(); ok {
		// Retention runs at every start. It is maintenance, not part of
		// the decision: a failure here neither blocks nor allows the
		// event (the event's own session still fails closed on its own
		// path), and nothing is written to stderr, which belongs to the
		// host protocol. `veil store sweep` reports the same sweep.
		_, _ = store.Sweep(ttl, startupSweepLimit)
	}
	return &engine{
		evaluator:       domain.NewPolicy(registry, store),
		registry:        registry,
		policyDigest:    p.Digest(),
		policyVersion:   p.Version,
		catalogRevision: revision,
		evidenceFile:    os.Getenv(evidenceFileEnv),
	}, nil
}

// decide evaluates event and builds its evidence record. The record is
// appended to the evidence file, when one is configured, before the
// caller writes any answer: a record that cannot be written fails the
// event closed with problem.EvidenceWrite (HCS-0005-R012), so no decision
// is ever acted on without its record.
func (e *engine) decide(host domain.Host, event domain.Event) (domain.Decision, []byte, problem.Code) {
	start := time.Now()
	decision, err := e.evaluator.Evaluate(event)
	if err != nil {
		return domain.Decision{}, nil, classifyEvaluateError(err)
	}
	elapsed := time.Since(start)

	id, err := evidence.NewID()
	if err != nil {
		return domain.Decision{}, nil, problem.Internal
	}
	rec, err := evidence.Build(evidence.Input{
		ID:              id,
		Time:            start,
		Host:            host,
		Event:           event.Kind,
		Tool:            event.ToolName,
		Session:         event.SessionID,
		Action:          decision.Kind,
		Findings:        e.registry.DetectAll(event),
		PolicyDigest:    e.policyDigest,
		PolicyVersion:   e.policyVersion,
		CatalogRevision: e.catalogRevision,
		Duration:        elapsed,
	})
	if err != nil {
		return domain.Decision{}, nil, problem.Internal
	}
	if e.evidenceFile != "" {
		if err := evidence.Append(e.evidenceFile, rec); err != nil {
			return domain.Decision{}, nil, problem.EvidenceWrite
		}
	}
	raw, err := evidence.Marshal(rec)
	if err != nil {
		return domain.Decision{}, nil, problem.Internal
	}
	return decision, raw, ""
}

// keyring is the OS keyring the store key falls back to. Tests replace it
// with a fake so they never touch the real keyring.
var keyring pseudonymstore.Keyring = pseudonymstore.OSKeyring{}

// startupSweepLimit bounds how many expired sessions one veil start
// removes, so a hook call never does unbounded work; the rest go on the
// next starts or with `veil store sweep`.
const startupSweepLimit = 16

// clock is the time the store reads for last use and retention. Tests
// move it instead of waiting.
var clock = time.Now

// newStore builds the pseudonym store under DefaultDir, with its key from
// VEIL_KEY_FD, then $CREDENTIALS_DIRECTORY, then the OS keyring.
func newStore() *pseudonymstore.FileStore {
	dir := pseudonymstore.DefaultDir()
	return pseudonymstore.NewFileStore(dir, pseudonymstore.NewKeyChainFromEnv(dir, keyring)).
		WithClock(func() time.Time { return clock() })
}

// hostProfile is one host veil can answer: how it handles an event and
// which exit code fails closed on it.
type hostProfile struct {
	handle      func(e *engine, raw []byte, stdout, stderr io.Writer) (exitCode int, failure problem.Code)
	failureExit int
}

// fail reports code as one problem line on w and returns the host's
// failed-closed exit code. The exit code carries the failure class, so a
// problem line that cannot be written is dropped (here and in every other
// problem.Write call): the host still sees a failure.
func (h hostProfile) fail(w io.Writer, code problem.Code) int {
	_ = problem.Write(w, problem.New(code))
	return h.failureExit
}

var hostsByName = map[string]hostProfile{
	"claude-code": {handle: runClaudeCode, failureExit: claudecode.FailureExitCode},
	"opencode":    {handle: runOpenCode, failureExit: opencode.FailureExitCode},
}

// run implements the CLI: `policy`, `store` and `acs` go to their
// runners; otherwise
// it reads exactly one JSON event from stdin,
// dispatches on the requested host, and returns the process exit code.
// Every failure is one RFC 9457 problem line on stderr (see
// internal/problem) and nothing on stdout. It is split out from main so
// tests can inject buffers instead of the real stdio.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) >= 1 && args[0] == "policy" {
		return runPolicy(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "store" {
		return runStore(args[1:], stdin, stdout, stderr)
	}
	if len(args) == 1 && args[0] == "acs" {
		return runACS(stdin, stdout, stderr)
	}
	if len(args) != 1 {
		_ = problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	}
	host, known := hostsByName[args[0]]
	if !known {
		_ = problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		return host.fail(stderr, problem.InputInvalid)
	}

	e, err := newEngine()
	if err != nil {
		return host.fail(stderr, classifyPolicyError(err))
	}

	exitCode, failure := host.handle(e, raw, stdout, stderr)
	if failure != "" {
		return host.fail(stderr, failure)
	}
	return exitCode
}

// classifyPolicyError maps a newEngine error to its problem code by error
// type: a *policy.Error carries its own code (policy or catalog).
func classifyPolicyError(err error) problem.Code {
	var perr *policy.Error
	switch {
	case errors.As(err, &perr):
		return perr.Code
	case errors.Is(err, evidence.ErrRevisionInvalid):
		return problem.CatalogRevisionInvalid
	default:
		return problem.Internal
	}
}

// classifyEvaluateError maps a Policy.Evaluate error to its problem code
// by error type, never by message. Evaluate fails either because the host
// lacks a capability or because the pseudonym store failed.
func classifyEvaluateError(err error) problem.Code {
	var unsupported *domain.UnsupportedCapabilityError
	var syntax *json.SyntaxError
	var mistyped *json.UnmarshalTypeError
	var pathErr *fs.PathError
	if code, ok := classifyStoreError(err); ok {
		return code
	}
	switch {
	case errors.As(err, &unsupported):
		return problem.CapabilityUnsupported
	case errors.As(err, &syntax), errors.As(err, &mistyped):
		return problem.StoreCorrupt
	case errors.As(err, &pathErr):
		return problem.StoreIO
	default:
		return problem.Internal
	}
}

// storeErrors maps each pseudonym store sentinel to its problem code.
var storeErrors = []struct {
	err  error
	code problem.Code
}{
	{pseudonymstore.ErrLocked, problem.StoreLocked},
	{pseudonymstore.ErrSessionRetired, problem.SessionRetired},
	{pseudonymstore.ErrSessionIDMissing, problem.SessionIDMissing},
	{pseudonymstore.ErrKeyMissing, problem.StoreKeyMissing},
	{pseudonymstore.ErrKeyInvalid, problem.StoreKeyInvalid},
	{pseudonymstore.ErrKeyringUnavailable, problem.StoreKeyringUnavailable},
	{pseudonymstore.ErrCorrupt, problem.StoreCorrupt},
}

// classifyStoreError maps a pseudonym store failure to its problem code
// by sentinel (errors.Is), never by message.
func classifyStoreError(err error) (problem.Code, bool) {
	for _, e := range storeErrors {
		if errors.Is(err, e.err) {
			return e.code, true
		}
	}
	return "", false
}

// runClaudeCode answers a Claude Code hook. Its stdout stays exactly the
// hook protocol: evidence goes only to the evidence file, because it is
// unverified whether Claude Code tolerates unknown members.
func runClaudeCode(e *engine, raw []byte, stdout, stderr io.Writer) (int, problem.Code) {
	event, err := claudecode.Decode(raw)
	if err != nil {
		return 0, problem.InputInvalid
	}

	decision, _, failure := e.decide(domain.HostClaudeCode, event)
	if failure != "" {
		return 0, failure
	}

	result, err := claudecode.Encode(event, decision)
	if err != nil {
		return 0, problem.Internal
	}

	// An answer that does not reach Claude Code must fail closed: exit 0 with
	// no stdout would let the original input proceed.
	if _, err := stdout.Write(result.Stdout); err != nil {
		return 0, problem.Internal
	}
	// The exit code alone carries a block, so a lost reason does not fail open.
	_, _ = stderr.Write(result.Stderr)
	return result.ExitCode, ""
}

// runOpenCode answers the OpenCode shim, with the evidence record as an
// additive evidence member of its answer.
func runOpenCode(e *engine, raw []byte, stdout, stderr io.Writer) (int, problem.Code) {
	event, err := opencode.Decode(raw)
	if err != nil {
		return 0, problem.InputInvalid
	}

	decision, record, failure := e.decide(domain.HostOpenCode, event)
	if failure != "" {
		return 0, failure
	}

	result, err := opencode.EncodeWithEvidence(event, decision, record)
	if err != nil {
		return 0, problem.Internal
	}

	if _, err := stdout.Write(result.Stdout); err != nil {
		return 0, problem.Internal
	}
	return result.ExitCode, ""
}

// runPolicy validates a policy and prints its version and digest as one
// JSON object: the file given as the only argument, else the file in
// VEIL_POLICY, else the embedded default policy. A failure is one problem
// line on stderr and exit ExitFailedClosed (ExitUsage for bad arguments),
// so a policy can be checked before it is deployed.
func runPolicy(args []string, stdout, stderr io.Writer) int {
	var (
		p      *policy.Policy
		err    error
		source string
	)
	switch {
	case len(args) > 1:
		_ = problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	case len(args) == 1:
		source = args[0] // #nosec G602 -- guarded by len(args) == 1
		p, err = policy.Load(source)
	case os.Getenv(policy.EnvVar) != "":
		source = os.Getenv(policy.EnvVar)
		p, err = policy.FromEnv()
	default:
		source = "default"
		p = policy.Default()
	}
	if err != nil {
		_ = problem.Write(stderr, problem.New(classifyPolicyError(err)))
		return problem.ExitFailedClosed
	}
	out, err := json.Marshal(struct {
		Source  string `json:"source"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
	}{source, p.Version, p.Digest()})
	if err != nil {
		_ = problem.Write(stderr, problem.New(problem.Internal))
		return problem.ExitFailedClosed
	}
	if _, err := fmt.Fprintln(stdout, string(out)); err != nil {
		_ = problem.Write(stderr, problem.New(problem.Internal))
		return problem.ExitFailedClosed
	}
	return problem.ExitDecision
}
