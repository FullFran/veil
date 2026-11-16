// Command veil-eval measures veil's detectors against the Spanish
// evaluation corpus: precision, recall and F1 per label, span-level
// micro-F1 (MEDDOCAN strict convention) and Evaluate latency per event.
//
//	go run ./cmd/veil-eval                  # print the table
//	go run ./cmd/veil-eval -check           # also fail if below baseline.json
//	go run ./cmd/veil-eval -write-baseline  # pin the current numbers
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/FullFran/veil/internal/eval"
	"github.com/FullFran/veil/internal/policy"
)

const (
	exitOK        = 0
	exitViolation = 1
	exitUsage     = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("veil-eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", filepath.Join("testdata", "corpus", "es", "v1"), "corpus directory (corpus.jsonl, catalog.json, baseline.json)")
	policyPath := fs.String("policy", "", "policy file (default: the embedded default policy)")
	baselinePath := fs.String("baseline", "", "baseline file (default: <corpus>/baseline.json)")
	check := fs.Bool("check", false, "exit 1 if recall on any label or p95 latency is worse than the baseline")
	writeBaseline := fs.Bool("write-baseline", false, "write the current numbers as the baseline")
	budget := fs.Float64("latency-budget-us", 0, "p95 latency budget per event in microseconds, for -write-baseline (default: keep the existing one, else 2000)")
	repeats := fs.Int("repeats", 20, "evaluations per event for latency")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "veil-eval: unexpected arguments")
		return exitUsage
	}
	if *baselinePath == "" {
		*baselinePath = filepath.Join(*corpusDir, "baseline.json")
	}

	p := policy.Default()
	if *policyPath != "" {
		var err error
		if p, err = policy.Load(*policyPath); err != nil {
			fmt.Fprintf(stderr, "veil-eval: %v\n", err)
			return exitUsage
		}
	}
	corpus, err := eval.LoadCorpus(*corpusDir)
	if err != nil {
		fmt.Fprintf(stderr, "veil-eval: %v\n", err)
		return exitUsage
	}
	report, err := eval.Run(corpus, p, eval.Options{Repeats: *repeats})
	if err != nil {
		fmt.Fprintf(stderr, "veil-eval: %v\n", err)
		return exitUsage
	}

	if *asJSON {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		printTable(stdout, report)
	}

	if *writeBaseline {
		if *budget == 0 {
			*budget = 2000
			if old, err := eval.LoadBaseline(*baselinePath); err == nil && old.LatencyP95BudgetMicro > 0 {
				*budget = old.LatencyP95BudgetMicro
			}
		}
		b, _ := json.MarshalIndent(eval.BaselineFrom(report, *budget), "", "  ")
		if err := os.WriteFile(*baselinePath, append(b, '\n'), 0o644); err != nil { // #nosec G306 -- the baseline is a public, committed file
			fmt.Fprintf(stderr, "veil-eval: %v\n", err)
			return exitUsage
		}
	}

	if *check {
		base, err := eval.LoadBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "veil-eval: %v\n", err)
			return exitUsage
		}
		if violations := eval.Check(report, base); len(violations) > 0 {
			for _, v := range violations {
				b, _ := json.Marshal(v)
				fmt.Fprintf(stderr, "veil-eval: below baseline: %s\n", b)
			}
			return exitViolation
		}
	}
	return exitOK
}

func printTable(w io.Writer, r eval.Report) {
	fmt.Fprintf(w, "corpus %s, %d cases, policy %s\n\n", r.Corpus, r.Cases, r.Policy)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "label\ttp\tfp\tfn\tprecision\trecall\tf1\t")
	row := func(name string, c eval.Counts) {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%.4f\t%.4f\t%.4f\t\n", name, c.TP, c.FP, c.FN, c.Precision(), c.Recall(), c.F1())
	}
	for _, label := range eval.Labels {
		row(label, r.Labels[label])
	}
	row("micro", r.Micro)
	_ = tw.Flush() // a short report on stdout; the exit code does not depend on it
	fmt.Fprintf(w, "\nlatency per event (Evaluate, %d samples): p50 %.1f µs, p95 %.1f µs, max %.1f µs\n",
		r.Latency.Samples, r.Latency.P50Micro, r.Latency.P95Micro, r.Latency.MaxMicro)
}
