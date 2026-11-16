// Command veil is the host-agnostic entrypoint invoked by a Claude Code
// hook or the OpenCode shim. It reads one JSON event on stdin, evaluates
// it against veil's privacy policy, and writes the host's expected
// response to stdout/stderr with the matching exit code. A failure is one
// RFC 9457 problem details line on stderr; the exit code carries only its
// class (see internal/problem and the README). `veil store reveal|forget
// <session>` serves a host the pseudonym store instead (see store.go).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/claudecode"
	"github.com/FullFran/veil/internal/hosts/opencode"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// newPolicy builds the veil policy shared by every host from the policy
// file in VEIL_POLICY (or the embedded default policy when it is unset).
// It returns an error instead of a *domain.Policy if the policy file, or
// the name catalog it uses, cannot be loaded: startup fails closed rather
// than silently running with a different policy.
func newPolicy() (*domain.Policy, error) {
	p, err := policy.FromEnv()
	if err != nil {
		return nil, err
	}
	registry, err := p.Registry(os.Getenv("VEIL_CATALOG"))
	if err != nil {
		return nil, err
	}
	return domain.NewPolicy(registry, newStore()), nil
}

// keyring is the OS keyring the store key falls back to. Tests replace it
// with a fake so they never touch the real keyring.
var keyring pseudonymstore.Keyring = pseudonymstore.OSKeyring{}

// newStore builds the pseudonym store under DefaultDir, with its key from
// VEIL_KEY_FD, then $CREDENTIALS_DIRECTORY, then the OS keyring.
func newStore() *pseudonymstore.FileStore {
	dir := pseudonymstore.DefaultDir()
	return pseudonymstore.NewFileStore(dir, pseudonymstore.NewKeyChainFromEnv(dir, keyring))
}

// hostProfile is one host veil can answer: how it handles an event and
// which exit code fails closed on it.
type hostProfile struct {
	handle      func(policy *domain.Policy, raw []byte, stdout, stderr io.Writer) (exitCode int, failure problem.Code)
	failureExit int
}

// fail reports code as one problem line on w and returns the host's
// failed-closed exit code.
func (h hostProfile) fail(w io.Writer, code problem.Code) int {
	problem.Write(w, problem.New(code))
	return h.failureExit
}

var hostsByName = map[string]hostProfile{
	"claude-code": {handle: runClaudeCode, failureExit: claudecode.FailureExitCode},
	"opencode":    {handle: runOpenCode, failureExit: opencode.FailureExitCode},
}

// run implements the CLI: `policy` and `store` subcommands go to their
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
		return runStore(args[1:], stdout, stderr)
	}
	if len(args) != 1 {
		problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	}
	host, known := hostsByName[args[0]]
	if !known {
		problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		return host.fail(stderr, problem.InputInvalid)
	}

	policy, err := newPolicy()
	if err != nil {
		return host.fail(stderr, classifyPolicyError(err))
	}

	exitCode, failure := host.handle(policy, raw, stdout, stderr)
	if failure != "" {
		return host.fail(stderr, failure)
	}
	return exitCode
}

// classifyPolicyError maps a newPolicy error to its problem code by error
// type: a *policy.Error carries its own code (policy or catalog).
func classifyPolicyError(err error) problem.Code {
	var perr *policy.Error
	if errors.As(err, &perr) {
		return perr.Code
	}
	return problem.Internal
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

func runClaudeCode(policy *domain.Policy, raw []byte, stdout, stderr io.Writer) (int, problem.Code) {
	event, err := claudecode.Decode(raw)
	if err != nil {
		return 0, problem.InputInvalid
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		return 0, classifyEvaluateError(err)
	}

	result, err := claudecode.Encode(event, decision)
	if err != nil {
		return 0, problem.Internal
	}

	stdout.Write(result.Stdout)
	stderr.Write(result.Stderr)
	return result.ExitCode, ""
}

func runOpenCode(policy *domain.Policy, raw []byte, stdout, stderr io.Writer) (int, problem.Code) {
	event, err := opencode.Decode(raw)
	if err != nil {
		return 0, problem.InputInvalid
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		return 0, classifyEvaluateError(err)
	}

	result, err := opencode.Encode(event, decision)
	if err != nil {
		return 0, problem.Internal
	}

	stdout.Write(result.Stdout)
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
		problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	case len(args) == 1:
		source = args[0]
		p, err = policy.Load(args[0])
	case os.Getenv(policy.EnvVar) != "":
		source = os.Getenv(policy.EnvVar)
		p, err = policy.FromEnv()
	default:
		source = "default"
		p = policy.Default()
	}
	if err != nil {
		problem.Write(stderr, problem.New(classifyPolicyError(err)))
		return problem.ExitFailedClosed
	}
	out, err := json.Marshal(struct {
		Source  string `json:"source"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
	}{source, p.Version, p.Digest()})
	if err != nil {
		problem.Write(stderr, problem.New(problem.Internal))
		return problem.ExitFailedClosed
	}
	fmt.Fprintln(stdout, string(out))
	return problem.ExitDecision
}
