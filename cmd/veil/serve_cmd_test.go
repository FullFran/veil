package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/ner"
	"github.com/FullFran/veil/internal/problem"
)

// fakeSidecarScript records the environment veil model serve gives it
// in $OUT and exits 7.
const fakeSidecarScript = `printf '%s\n%s\n' "$VEIL_NER_SOCKET" "$VEIL_NER_MODEL_DIR" > "$OUT"; printf '%s' "$VEIL_NER_ENTRY" > "$OUT.entry"; exit 7`

// serveEnv selects test-model with a policy, optionally pulls it, and
// returns the cache root, the socket path and the record file.
func serveEnv(t *testing.T, pull bool) (string, string, string) {
	t.Helper()
	cache, _ := modelEnv(t, modelBody)
	t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"ner":{"action":"rewrite"}}}`))
	t.Setenv("VEIL_NER_MODEL", "test-model")
	socket := filepath.Join(t.TempDir(), "run", "veil", "ner.sock")
	t.Setenv("VEIL_NER_SOCKET", socket)
	out := filepath.Join(t.TempDir(), "env")
	t.Setenv("OUT", out)
	if pull {
		if code, _, stderr := runModelCmd(t, "pull", "test-model", "--accept-license", "Apache-2.0"); code != 0 {
			t.Fatalf("pull: %s", stderr)
		}
	}
	return cache, socket, out
}

func TestModelServe_RunsTheSidecarWithTheVerifiedModel(t *testing.T) {
	cache, socket, out := serveEnv(t, true)

	code, _, stderr := runModelCmd(t, "serve", "sh", "-c", fakeSidecarScript)
	if code != 7 {
		t.Fatalf("exit %d (stderr %s), want the sidecar's exit code 7", code, stderr)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := socket + "\n" + filepath.Join(cache, "test-model", "r1") + "\n"
	if string(got) != want {
		t.Fatalf("sidecar env = %q, want %q", got, want)
	}
	entryJSON, err := os.ReadFile(out + ".entry")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ner.LoadCatalog(os.Getenv("VEIL_NER_CATALOG"))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := c.Lookup("test-model")
	sum := sha256.Sum256(entryJSON)
	if "sha256:"+hex.EncodeToString(sum[:]) != entry.Digest() {
		t.Fatalf("VEIL_NER_ENTRY %s does not hash to the entry digest the client expects", entryJSON)
	}
	info, err := os.Stat(filepath.Dir(socket))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory: %v, mode %v; want it created 0700", err, info.Mode().Perm())
	}
}

func TestModelServe_Failures(t *testing.T) {
	cases := map[string]struct {
		pull  bool
		setup func(t *testing.T)
		args  []string
		exit  int
		want  problem.Code
	}{
		"model not pulled": {false, nil, []string{"sh", "-c", fakeSidecarScript}, problem.ExitFailedClosed, problem.ModelMissing},
		"no command":       {true, nil, nil, problem.ExitUsage, problem.Usage},
		"no model selected": {true, func(t *testing.T) {
			t.Setenv("VEIL_POLICY", "")
			t.Setenv("VEIL_NER_MODEL", "")
		}, []string{"sh", "-c", fakeSidecarScript}, problem.ExitUsage, problem.Usage},
		"command not found": {true, nil, []string{"/nonexistent/veil-sidecar"}, problem.ExitFailedClosed, problem.NERUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, out := serveEnv(t, tc.pull)
			if tc.setup != nil {
				tc.setup(t)
			}
			code, _, stderr := runModelCmd(t, append([]string{"serve"}, tc.args...)...)
			if code != tc.exit {
				t.Fatalf("exit %d (stderr %s), want %d", code, stderr, tc.exit)
			}
			assertProblem(t, stderr, tc.want)
			if _, err := os.Stat(out); err == nil {
				t.Fatal("the sidecar ran")
			}
		})
	}
}

func TestModelServe_ForwardsTerminationToTheSidecar(t *testing.T) {
	_, _, out := serveEnv(t, true)
	// The sidecar exits 0 on SIGTERM, after saying it is ready.
	script := `trap 'echo stopped > "$OUT"; exit 0' TERM; echo ready > "$OUT.ready"; while :; do sleep 0.05; done`

	done := make(chan int, 1)
	go func() {
		code, _, _ := runModelCmd(t, "serve", "sh", "-c", script)
		done <- code
	}()
	waitFor(t, out+".ready")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d, want the sidecar's 0", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop the sidecar")
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "stopped\n" {
		t.Fatalf("sidecar record %q, %v; want it stopped by SIGTERM", got, err)
	}
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s did not appear", path)
}
