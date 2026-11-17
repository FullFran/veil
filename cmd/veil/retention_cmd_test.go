package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

var day0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// setClock moves veil's clock to at for the rest of the test.
func setClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := clock
	clock = func() time.Time { return at }
	t.Cleanup(func() { clock = prev })
}

// seed mints a token for value in session at day0 through the real store.
func seed(t *testing.T, session, category, value string) {
	t.Helper()
	setClock(t, day0)
	if _, err := newStore().Token(session, category, value); err != nil {
		t.Fatal(err)
	}
}

// hasSession reports whether the session still has a store (its counters
// file, which outlives removal and holds no value, does not count).
func hasSession(t *testing.T, session string) bool {
	t.Helper()
	stem := filepath.Base(sessionFile(session, ""))
	entries, _ := os.ReadDir(filepath.Dir(sessionFile(session, "")))
	for _, e := range entries {
		if suffix, ok := strings.CutPrefix(e.Name(), stem); ok && suffix != ".ctr" && suffix != ".id" {
			return true
		}
	}
	return false
}

const ttlPolicy = `{"version":"1.0","detectors":{"dni":{"action":"rewrite"}},"store":{"ttl":"P1D"}}`

func swept(t *testing.T, stdout string) pseudonymstore.SweepResult {
	t.Helper()
	var r pseudonymstore.SweepResult
	if err := json.Unmarshal([]byte(stdout), &r); err != nil || r.Forgotten == nil || r.Skipped == nil || r.Failed == nil {
		t.Fatalf("stdout %q is not a sweep answer: %v", stdout, err)
	}
	return r
}

func TestRun_StoreSweep_RemovesExpired_KeepsUnexpired(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_POLICY", writePolicy(t, ttlPolicy))
	seed(t, "old", "DNI", "12345678Z")
	setClock(t, day0.Add(36*time.Hour))
	if _, err := newStore().Token("fresh", "DNI", "87654321X"); err != nil {
		t.Fatal(err)
	}
	setClock(t, day0.Add(48*time.Hour))

	exit, stdout, stderr := storeCmd("sweep")

	if exit != problem.ExitDecision || stderr != "" {
		t.Fatalf("sweep = (exit %d, stderr %q), want (0, empty)", exit, stderr)
	}
	if got := swept(t, stdout); !reflect.DeepEqual(got.Forgotten, []string{"old"}) {
		t.Fatalf("forgotten = %v, want [old]", got.Forgotten)
	}
	if hasSession(t, "old") || !hasSession(t, "fresh") {
		t.Fatalf("after sweep: old present = %v, fresh present = %v; want false, true", hasSession(t, "old"), hasSession(t, "fresh"))
	}
}

// TestRun_StartupSweep_RemovesExpired: every veil start sweeps when the
// policy sets a TTL, and the event itself still gets its decision.
func TestRun_StartupSweep_RemovesExpired(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_POLICY", writePolicy(t, ttlPolicy))
	seed(t, "old", "DNI", "12345678Z")
	setClock(t, day0.Add(48*time.Hour))

	if exit := run([]string{"opencode"}, strings.NewReader(dniTool), io.Discard, io.Discard); exit != 0 {
		t.Fatalf("event exit = %d, want 0", exit)
	}

	if hasSession(t, "old") {
		t.Fatal("startup did not sweep the expired session")
	}
	if !hasSession(t, "sess-1") {
		t.Fatal("the event's own session was not written")
	}
}

// TestRun_NoTTL_DeletesNothing guards existing users: without store.ttl
// neither startup nor an explicit sweep removes anything, however old.
func TestRun_NoTTL_DeletesNothing(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	seed(t, "old", "DNI", "12345678Z")
	setClock(t, day0.Add(10*365*24*time.Hour))

	if exit := run([]string{"opencode"}, strings.NewReader(dniTool), io.Discard, io.Discard); exit != 0 {
		t.Fatalf("event exit = %d, want 0", exit)
	}
	exit, stdout, _ := storeCmd("sweep")

	if exit != problem.ExitDecision || len(swept(t, stdout).Forgotten) != 0 || !hasSession(t, "old") {
		t.Fatalf("sweep without a TTL = (exit %d, %q), old present = %v; want nothing removed", exit, stdout, hasSession(t, "old"))
	}
}

func TestRun_StoreSweep_InvalidPolicy_FailsClosed(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"dni":{"action":"rewrite"}},"store":{"ttl":"30d"}}`))

	exit, stdout, stderr := storeCmd("sweep")

	if exit != problem.ExitFailedClosed || stdout != "" {
		t.Fatalf("sweep = (exit %d, stdout %q), want (%d, empty)", exit, stdout, problem.ExitFailedClosed)
	}
	assertProblem(t, stderr, problem.PolicyInvalid)
}

func found(t *testing.T, stdout string) []pseudonymstore.Holding {
	t.Helper()
	var out struct {
		Sessions []pseudonymstore.Holding `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil || out.Sessions == nil {
		t.Fatalf("stdout %q is not a find answer: %v", stdout, err)
	}
	return out.Sessions
}

// TestRun_StoreFind_MatchesCompactAndSeparatedForms_PrintsNoValue: one
// value written two ways is the same value, as detection keys it, and the
// answer carries session ids and categories only.
func TestRun_StoreFind_MatchesCompactAndSeparatedForms_PrintsNoValue(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if exit := run([]string{"opencode"}, strings.NewReader(dniTool), io.Discard, io.Discard); exit != 0 {
		t.Fatalf("rewrite exit = %d, want 0", exit)
	}
	seed(t, "other", "EMAIL", "ana@example.com")
	seed(t, "spaced", "IBAN", "ES9121000418450200051332")

	cases := []struct {
		value string
		want  []pseudonymstore.Holding
	}{
		{"12345678Z", []pseudonymstore.Holding{{Session: "sess-1", Categories: []string{"DNI"}}}},
		{"12.345.678-Z", []pseudonymstore.Holding{{Session: "sess-1", Categories: []string{"DNI"}}}},
		{"ES91 2100 0418 4502 0005 1332", []pseudonymstore.Holding{{Session: "spaced", Categories: []string{"IBAN"}}}},
		{"87654321X", []pseudonymstore.Holding{}},
	}
	for _, c := range cases {
		exit, stdout, stderr := storeCmd("find", "--value", c.value)
		if exit != problem.ExitDecision || stderr != "" {
			t.Fatalf("find %q = (exit %d, stderr %q), want (0, empty)", c.value, exit, stderr)
		}
		if got := found(t, stdout); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("find %q = %+v, want %+v", c.value, got, c.want)
		}
		for _, secret := range []string{"12345678", "ana@", "ES91", "2100"} {
			if strings.Contains(stdout, secret) {
				t.Fatalf("find %q printed a value: %q", c.value, stdout)
			}
		}
	}
}

// TestRun_StoreFind_ValueFromStdin keeps the value out of argv, where
// other local users and shell history can read it.
func TestRun_StoreFind_ValueFromStdin(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	seed(t, "sess-1", "DNI", "12345678Z")

	var stdout, stderr bytes.Buffer
	exit := run([]string{"store", "find", "--value", "-"}, strings.NewReader("12.345.678-Z\n"), &stdout, &stderr)

	want := []pseudonymstore.Holding{{Session: "sess-1", Categories: []string{"DNI"}}}
	if exit != problem.ExitDecision || !reflect.DeepEqual(found(t, stdout.String()), want) {
		t.Fatalf("find from stdin = (exit %d, %q, stderr %q), want sess-1", exit, stdout.String(), stderr.String())
	}
}

func TestRun_StoreFind_MissingOrWrongKey_FailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		want  problem.Code
	}{
		{"missing key", func(t *testing.T) {
			useKeyring(t, newFakeKeyring())
			foreignSession(t)
			useKeyring(t, newFakeKeyring())
		}, problem.StoreKeyMissing},
		{"wrong key", func(t *testing.T) {
			kr := newFakeKeyring()
			useKeyring(t, kr)
			foreignSession(t)
			id, _ := age.GenerateX25519Identity()
			kr.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = id.String()
		}, problem.StoreKeyInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			c.setup(t)

			exit, stdout, stderr := storeCmd("find", "--value", "12345678Z")

			if exit != problem.ExitFailedClosed || stdout != "" {
				t.Fatalf("find = (exit %d, stdout %q), want (%d, empty)", exit, stdout, problem.ExitFailedClosed)
			}
			assertProblem(t, stderr, c.want)
		})
	}
}

// TestRun_StoreForget_SeveralSessions_NeedsNoKey is the erasure half of
// find-then-forget; forget stays keyless so a lost key never blocks it.
func TestRun_StoreForget_SeveralSessions_NeedsNoKey(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	seed(t, "a", "DNI", "12345678Z")
	seed(t, "b", "DNI", "12345678Z")
	seed(t, "c", "DNI", "87654321X")
	useKeyring(t, newFakeKeyring())

	exit, stdout, stderr := storeCmd("forget", "a", "b")

	if exit != problem.ExitDecision || stdout != "" || stderr != "" {
		t.Fatalf("forget = (exit %d, %q, %q), want (0, empty, empty)", exit, stdout, stderr)
	}
	if hasSession(t, "a") || hasSession(t, "b") || !hasSession(t, "c") {
		t.Fatal("forget a b must remove a and b and keep c")
	}
}

func TestRun_StoreRetention_BadUsage(t *testing.T) {
	for _, args := range [][]string{{"sweep", "x"}, {"find"}, {"find", "x"}, {"find", "--value"}, {"find", "--value", ""}, {"find", "--value", "a", "b"}, {"forget", "a", ""}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			exit, stdout, stderr := storeCmd(args...)
			if exit != problem.ExitUsage || stdout != "" {
				t.Fatalf("store %v = (exit %d, stdout %q), want (%d, empty)", args, exit, stdout, problem.ExitUsage)
			}
			assertProblem(t, stderr, problem.Usage)
		})
	}
}

// TestRun_StoreSweep_PartialFailure_ReportsAndExitsOne: a session that
// cannot be removed does not stop the sweep; the answer lists it under
// failed (ids only) and the command still fails closed.
func TestRun_StoreSweep_PartialFailure_ReportsAndExitsOne(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("VEIL_POLICY", writePolicy(t, ttlPolicy))
	seed(t, "a1", "DNI", "12345678Z")
	seed(t, "b2", "DNI", "12345678Z")
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), sessionFile("a1", ".lock")); err != nil {
		t.Fatal(err)
	}
	setClock(t, day0.Add(48*time.Hour))

	exit, stdout, stderr := storeCmd("sweep")

	if exit != problem.ExitFailedClosed {
		t.Fatalf("sweep exit = %d, want %d", exit, problem.ExitFailedClosed)
	}
	got := swept(t, stdout)
	if !reflect.DeepEqual(got.Failed, []string{"a1"}) || !reflect.DeepEqual(got.Forgotten, []string{"b2"}) {
		t.Fatalf("sweep = %+v, want a1 failed and b2 forgotten", got)
	}
	assertProblem(t, stderr, problem.StoreIO)
}
