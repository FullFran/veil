// Command veil is the host-agnostic entrypoint invoked by a Claude Code
// hook or the OpenCode shim. It reads one JSON event on stdin, evaluates
// it against veil's privacy policy, and writes the host's expected
// response to stdout/stderr with the matching exit code.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/claudecode"
	"github.com/FullFran/veil/internal/hosts/opencode"
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

// run implements the CLI: it reads exactly one JSON event from stdin,
// dispatches on the requested host, and returns the process exit code.
// It is split out from main so tests can inject buffers instead of the
// real stdio.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: veil <claude-code|opencode>")
		return 1
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "veil: read stdin: %v\n", err)
		return 1
	}

	policy, err := newPolicy()
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	switch args[0] {
	case "claude-code":
		return runClaudeCode(policy, raw, stdout, stderr)
	case "opencode":
		return runOpenCode(policy, raw, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "veil: unknown host %q (want claude-code or opencode)\n", args[0])
		return 1
	}
}

func runClaudeCode(policy *domain.Policy, raw []byte, stdout, stderr io.Writer) int {
	event, err := claudecode.Decode(raw)
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	result, err := claudecode.Encode(event, decision)
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	stdout.Write(result.Stdout)
	stderr.Write(result.Stderr)
	return result.ExitCode
}

func runOpenCode(policy *domain.Policy, raw []byte, stdout, stderr io.Writer) int {
	event, err := opencode.Decode(raw)
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	decision, err := policy.Evaluate(event)
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	result, err := opencode.Encode(decision)
	if err != nil {
		fmt.Fprintf(stderr, "veil: %v\n", err)
		return 1
	}

	stdout.Write(result.Stdout)
	return result.ExitCode
}
