package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// e2eEnvVar opts in to the end-to-end test with the real model: it needs
// uv, network for the sidecar's Python dependencies on first run, and
// gliner2-pii pulled into the veil model cache (veil model pull
// gliner2-pii --accept-license Apache-2.0).
const e2eEnvVar = "VEIL_NER_E2E"

// TestE2E_RealSidecarRewritesAName runs the reference sidecar under
// `veil model serve` with the pinned GLiNER2-PII model and checks that
// veil, as an opencode hook, pseudonymizes a Spanish name only the model
// can find (no name catalog, no rule detector).
func TestE2E_RealSidecarRewritesAName(t *testing.T) {
	if os.Getenv(e2eEnvVar) != "1" {
		t.Skipf("set %s=1 to run against the real model", e2eEnvVar)
	}
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Fatal("uv is required")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "veil")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir, err := os.MkdirTemp("", "ner-e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "ner.sock")
	// evidenceEnv clears VEIL_POLICY; the policy is set below.
	t.Setenv("VEIL_NER_SOCKET", socket)
	t.Setenv("VEIL_NER_MODEL", "")
	t.Setenv("VEIL_NER_CATALOG", "")
	evidence := evidenceEnv(t)
	t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"ner":{"action":"rewrite","model":"gliner2-pii","timeoutMs":30000}}}`))

	sidecar := filepath.Join(repo, "adapters", "ner-sidecar")
	serve := exec.Command(bin, "model", "serve", uv, "run", "--project", sidecar, "--frozen", "python", filepath.Join(sidecar, "veil_ner_sidecar.py")) // #nosec G204 -- test-built binary
	var serveErr strings.Builder
	serve.Stdout, serve.Stderr = &serveErr, &serveErr
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- serve.Wait() }()
	t.Cleanup(func() { _ = serve.Process.Kill() })

	deadline := time.Now().Add(10 * time.Minute)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("serve exited before listening: %v\n%s", err, serveErr.String())
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sidecar did not listen in time\n%s", serveErr.String())
		}
	}

	const name = "Íñigo Etxeberria"
	payload := `{"event":"tool.execute.before","sessionID":"s1","tool":"bash","args":{"command":"echo 'Reunión con ` + name + ` el lunes'"}}`
	start := time.Now()
	code, stdout, stderr := runNER(t, payload)
	t.Logf("first event: %v", time.Since(start))
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if strings.Contains(stdout, "Etxeberria") || !strings.Contains(stdout, "[NOMBRE-001]") {
		t.Fatalf("stdout = %s, want the name pseudonymized by the model", stdout)
	}
	records := readRecords(t, evidence)
	if len(records) != 1 || member(t, records[0], "data", "unmapped", "veil", "ner_model") == nil {
		t.Fatalf("evidence = %+v, want one record naming the model", records)
	}

	if err := serve.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("serve exited %v, want 0 after SIGTERM\n%s", err, serveErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop after SIGTERM")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket after stop: %v, want it removed", err)
	}
}
