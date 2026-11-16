package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

// revealed decodes a `veil store reveal` answer.
func revealed(t *testing.T, stdout string) []pseudonymstore.Marker {
	t.Helper()
	var out struct {
		Markers []pseudonymstore.Marker `json:"markers"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout %q is not a reveal answer: %v", stdout, err)
	}
	if out.Markers == nil {
		t.Fatalf("stdout %q has no markers array", stdout)
	}
	return out.Markers
}

func storeCmd(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exit := run(append([]string{"store"}, args...), strings.NewReader(""), &stdout, &stderr)
	return exit, stdout.String(), stderr.String()
}

func TestRun_StoreReveal_ListsWhatVeilHid(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if exit := run([]string{"opencode"}, strings.NewReader(dniTool), io.Discard, io.Discard); exit != 0 {
		t.Fatalf("rewrite exit = %d, want 0", exit)
	}

	exit, stdout, stderr := storeCmd("reveal", "sess-1")

	if exit != problem.ExitDecision || stderr != "" {
		t.Fatalf("reveal = (exit %d, stderr %q), want (0, empty)", exit, stderr)
	}
	want := []pseudonymstore.Marker{{Marker: "[DNI-001]", Category: "DNI", Value: "12345678Z"}}
	if got := revealed(t, stdout); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("markers = %v, want %v", got, want)
	}
}

func TestRun_StoreReveal_UnknownSession_IsEmpty(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	exit, stdout, stderr := storeCmd("reveal", "never-seen")

	if exit != problem.ExitDecision || stderr != "" {
		t.Fatalf("reveal = (exit %d, stderr %q), want (0, empty)", exit, stderr)
	}
	if got := revealed(t, stdout); len(got) != 0 {
		t.Fatalf("markers = %v, want none", got)
	}
}

func TestRun_StoreReveal_WrongKey_FailsClosed(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	kr := newFakeKeyring()
	useKeyring(t, kr)
	foreignSession(t)
	id, _ := age.GenerateX25519Identity()
	kr.secrets[pseudonymstore.KeyringService+"/"+pseudonymstore.KeyringAccount] = id.String()

	exit, stdout, stderr := storeCmd("reveal", "sess-1")

	if exit != problem.ExitFailedClosed || stdout != "" {
		t.Fatalf("reveal = (exit %d, stdout %q), want (%d, empty)", exit, stdout, problem.ExitFailedClosed)
	}
	assertProblem(t, stderr, problem.StoreKeyInvalid)
}

func TestRun_StoreForget_RemovesTheSession(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if exit := run([]string{"opencode"}, strings.NewReader(dniTool), io.Discard, io.Discard); exit != 0 {
		t.Fatalf("rewrite exit = %d, want 0", exit)
	}

	exit, stdout, stderr := storeCmd("forget", "sess-1")

	if exit != problem.ExitDecision || stdout != "" || stderr != "" {
		t.Fatalf("forget = (exit %d, stdout %q, stderr %q), want (0, empty, empty)", exit, stdout, stderr)
	}
	entries, err := os.ReadDir(sessionsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sess-1.") {
			t.Errorf("%s still exists after forget", e.Name())
		}
	}
}

func TestRun_StoreForget_UnknownSession_Succeeds(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	exit, stdout, stderr := storeCmd("forget", "never-seen")

	if exit != problem.ExitDecision || stdout != "" || stderr != "" {
		t.Fatalf("forget = (exit %d, stdout %q, stderr %q), want (0, empty, empty)", exit, stdout, stderr)
	}
}

func TestRun_Store_BadUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"reveal"}, {"forget"}, {"reveal", "a", "b"}, {"wipe", "a"}, {"reveal", ""}} {
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
