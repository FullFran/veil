package main

import (
	"encoding/json"
	"io"

	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

// runStore implements `veil store reveal <session>` and
// `veil store forget <session>`, so a host reads or deletes a session's
// pseudonyms through veil instead of parsing or removing its files.
// Success exits 0; a store failure is one problem line on stderr and
// exit 1; bad arguments exit 2.
func runStore(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[1] == "" {
		problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	}
	subcommand, session := args[0], args[1]

	switch subcommand {
	case "reveal":
		markers, err := newStore().Reveal(session)
		if err != nil {
			return failStore(stderr, err)
		}
		answer, err := json.Marshal(struct {
			Markers []pseudonymstore.Marker `json:"markers"`
		}{markers})
		if err != nil {
			return failStore(stderr, err)
		}
		stdout.Write(append(answer, '\n'))
		return problem.ExitDecision
	case "forget":
		if err := newStore().Forget(session); err != nil {
			return failStore(stderr, err)
		}
		return problem.ExitDecision
	default:
		problem.Write(stderr, problem.New(problem.Usage))
		return problem.ExitUsage
	}
}

// failStore reports a store command failure: the store's own code, an
// I/O failure, or VEIL_INTERNAL.
func failStore(stderr io.Writer, err error) int {
	problem.Write(stderr, problem.New(classifyEvaluateError(err)))
	return problem.ExitFailedClosed
}
