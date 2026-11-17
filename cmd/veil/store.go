package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

// maxFindValue bounds how much of stdin `store find --value -` reads.
const maxFindValue = 64 << 10

// runStore implements the `veil store` commands, so a host reads,
// searches or deletes pseudonym sessions through veil instead of parsing
// or removing its files:
//
//	veil store reveal <session>
//	veil store forget <session> [<session> ...]
//	veil store forget --legacy-stem <stem> [<stem> ...]
//	veil store find --value <value|->
//	veil store sweep
//
// Success exits 0 with one JSON line on stdout (none for forget); a
// failure is one problem line on stderr and exit 1, with an empty stdout
// except for a sweep that removed some sessions and failed on others,
// which still prints its answer; bad arguments exit 2.
func runStore(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch subcommand, rest := args[0], args[1:]; subcommand {
	case "reveal":
		if len(rest) != 1 || rest[0] == "" {
			return usage(stderr)
		}
		markers, err := newStore().Reveal(rest[0])
		if err != nil {
			return failStore(stderr, err)
		}
		return answer(stdout, stderr, struct {
			Markers []pseudonymstore.Marker `json:"markers"`
		}{markers})
	case "forget":
		forget := newStore().Forget
		if len(rest) > 0 && rest[0] == "--legacy-stem" {
			// A store a veil before #26 left under a name several session
			// ids shared: no session id reaches it, so it is named.
			forget, rest = newStore().ForgetLegacy, rest[1:]
		}
		if len(rest) == 0 {
			return usage(stderr)
		}
		for _, name := range rest {
			if name == "" {
				return usage(stderr)
			}
		}
		for _, name := range rest {
			err := forget(name)
			if errors.Is(err, pseudonymstore.ErrLegacyStemInvalid) {
				return usage(stderr)
			}
			if err != nil {
				return failStore(stderr, err)
			}
		}
		return problem.ExitDecision
	case "find":
		value, ok := findValue(rest, stdin)
		if !ok {
			return usage(stderr)
		}
		holdings, err := newStore().Find(canonicalForms(value))
		if err != nil {
			return failStore(stderr, err)
		}
		return answer(stdout, stderr, struct {
			Sessions []pseudonymstore.Holding `json:"sessions"`
		}{holdings})
	case "sweep":
		if len(rest) != 0 {
			return usage(stderr)
		}
		p, err := policy.FromEnv()
		if err != nil {
			_ = problem.Write(stderr, problem.New(classifyPolicyError(err)))
			return problem.ExitFailedClosed
		}
		result := pseudonymstore.NewSweepResult()
		if ttl, ok := p.Retention(); ok {
			result, err = newStore().Sweep(ttl, 0)
		}
		if err != nil && len(result.Failed) > 0 {
			// Partial: report what was done and what failed (ids only),
			// then fail closed.
			answer(stdout, stderr, result)
			return failStore(stderr, err)
		}
		if err != nil {
			return failStore(stderr, err)
		}
		return answer(stdout, stderr, result)
	default:
		return usage(stderr)
	}
}

// findValue reads `--value <v>`, or the value from stdin for `--value -`
// (trailing line break removed), so it can stay out of argv, which other
// local users and the shell history can read.
func findValue(args []string, stdin io.Reader) (string, bool) {
	if len(args) != 2 || args[0] != "--value" || args[1] == "" {
		return "", false
	}
	if args[1] != "-" {
		return args[1], true
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxFindValue+1))
	if err != nil || len(raw) > maxFindValue {
		return "", false
	}
	value := strings.TrimRight(string(raw), "\r\n")
	return value, value != ""
}

// canonicalForms returns the value as typed plus every canonical key veil's
// rewritable detectors give it (for example "12345678Z" for
// "12.345.678-Z"), so find matches a value however it was written, the
// way detection keyed it when the token was minted. All detectors run,
// whatever the current policy enables: a session may hold values from an
// earlier policy.
func canonicalForms(value string) []string {
	forms := []string{value}
	event := domain.Event{Kind: domain.EventPromptSubmit, Text: value}
	for _, d := range []domain.Detector{domain.NewDNIDetector(), domain.NewIBANDetector(), domain.NewEmailDetector(), domain.NewPhoneDetector()} {
		for _, f := range d.Detect(event) {
			if f.Key != "" {
				forms = append(forms, f.Key)
			} else if f.Match != "" {
				forms = append(forms, f.Match)
			}
		}
	}
	return forms
}

// answer writes v as one JSON line on stdout.
func answer(stdout, stderr io.Writer, v any) int {
	raw, err := json.Marshal(v)
	if err != nil {
		return failStore(stderr, err)
	}
	var line bytes.Buffer
	line.Write(raw)
	line.WriteByte('\n')
	if _, err := stdout.Write(line.Bytes()); err != nil {
		_ = problem.Write(stderr, problem.New(problem.Internal))
		return problem.ExitFailedClosed
	}
	return problem.ExitDecision
}

func usage(stderr io.Writer) int {
	_ = problem.Write(stderr, problem.New(problem.Usage))
	return problem.ExitUsage
}

// failStore reports a store command failure: the store's own code, an
// I/O failure, or VEIL_INTERNAL.
func failStore(stderr io.Writer, err error) int {
	_ = problem.Write(stderr, problem.New(classifyEvaluateError(err)))
	return problem.ExitFailedClosed
}
