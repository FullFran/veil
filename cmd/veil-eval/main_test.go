package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func corpusDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "corpus", "es", "v1")
}

func TestRun_Check_PassesOnCommittedBaseline(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-corpus", corpusDir(t), "-check", "-repeats", "5"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("no table printed")
	}
}

// TestRun_Check_FailsWhenRecallDrops: a baseline demanding perfect recall
// on every label must fail against the real corpus, which has known
// misses (foreign separated IBANs, names outside the catalog).
func TestRun_Check_FailsWhenRecallDrops(t *testing.T) {
	strict := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(strict, []byte(`{"recall":{"DNI":1,"IBAN":1,"EMAIL":1,"TEL":1,"NOMBRE":1},"latencyP95BudgetMicros":1000000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-corpus", corpusDir(t), "-baseline", strict, "-check", "-repeats", "1"}, &stdout, &stderr); code != exitViolation {
		t.Fatalf("exit = %d, want %d", code, exitViolation)
	}
}

func TestRun_Check_FailsOverLatencyBudget(t *testing.T) {
	tight := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(tight, []byte(`{"recall":{},"latencyP95BudgetMicros":0.000001}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-corpus", corpusDir(t), "-baseline", tight, "-check", "-repeats", "1"}, &stdout, &stderr); code != exitViolation {
		t.Fatalf("exit = %d, want %d", code, exitViolation)
	}
}

func TestRun_BadArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown flag":   {"-nope"},
		"extra argument": {"x"},
		"missing corpus": {"-corpus", filepath.Join(t.TempDir(), "absent")},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("exit = %d, want %d", code, exitUsage)
			}
		})
	}
}
