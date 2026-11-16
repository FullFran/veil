// Command veil is the host-agnostic entrypoint invoked by a Claude Code
// hook or the OpenCode shim. It reads one JSON event on stdin, evaluates
// it against veil's privacy policy, and writes the host's expected
// response to stdout/stderr with the matching exit code. A failure is one
// RFC 9457 problem details line on stderr; the exit code carries only its
// class (see internal/problem and the README).
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
	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// newPolicy builds the standard veil policy shared by every host. It
// returns an error instead of a *domain.Policy if VEIL_CATALOG is set but
// cannot be loaded: startup fails closed rather than silently running
// with an empty name catalog.
func newPolicy() (*domain.Policy, error) {
	detectors := []domain.Detector{
		domain.NewDNIDetector(),
		domain.NewIBANDetector(),
		domain.NewEmailDetector(),
		domain.NewPhoneDetector(),
		domain.NewSecretPathDetector(),
		domain.NewBinaryContentDetector(),
	}

	if catalogPath := os.Getenv("VEIL_CATALOG"); catalogPath != "" {
		names, err := domain.LoadNameCatalog(catalogPath)
		if err != nil {
			return nil, fmt.Errorf("veil: load VEIL_CATALOG: %w", err)
		}
		detectors = append(detectors, domain.NewNameCatalogDetector(names))
	}

	registry := domain.NewRegistry(detectors...)
	store := pseudonymstore.NewFileStore(pseudonymstore.DefaultDir())
	return domain.NewPolicy(registry, store), nil
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

// run implements the CLI: it reads exactly one JSON event from stdin,
// dispatches on the requested host, and returns the process exit code.
// Every failure is one RFC 9457 problem line on stderr (see
// internal/problem) and nothing on stdout. It is split out from main so
// tests can inject buffers instead of the real stdio.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
		return host.fail(stderr, problem.CatalogUnreadable)
	}

	exitCode, failure := host.handle(policy, raw, stdout, stderr)
	if failure != "" {
		return host.fail(stderr, failure)
	}
	return exitCode
}

// classifyEvaluateError maps a Policy.Evaluate error to its problem code
// by error type, never by message. Evaluate fails either because the host
// lacks a capability or because the pseudonym store failed.
func classifyEvaluateError(err error) problem.Code {
	var unsupported *domain.UnsupportedCapabilityError
	var syntax *json.SyntaxError
	var mistyped *json.UnmarshalTypeError
	var pathErr *fs.PathError
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
