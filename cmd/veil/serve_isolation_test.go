package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/problem"
)

func TestModelServe_PassesOnlyAnAllowListedEnvironment(t *testing.T) {
	_, socket, out := serveEnv(t, true)
	t.Setenv("VEIL_KEY_FD", "3")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "not-for-the-sidecar")
	t.Setenv("LANG", "C.UTF-8")
	t.Setenv("LC_ALL", "C.UTF-8")
	t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-cache")
	t.Setenv("HOME", "/tmp/home")

	code, _, stderr := runModelCmd(t, sidecar(`env > "$1"`, out)...)
	if code != 0 {
		t.Fatalf("exit %d (stderr %s), want 0", code, stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, _ := strings.Cut(line, "=")
		env[name] = value
	}
	for _, name := range []string{"VEIL_KEY_FD", "AWS_SECRET_ACCESS_KEY", "VEIL_POLICY", "VEIL_NER_MODEL", "VEIL_NER_CATALOG", "VEIL_MODEL_CACHE"} {
		if _, passed := env[name]; passed {
			t.Errorf("%s reached the sidecar", name)
		}
	}
	for name, want := range map[string]string{
		"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "XDG_CACHE_HOME": "/tmp/xdg-cache", "HOME": "/tmp/home",
		"PATH": os.Getenv("PATH"), "VEIL_NER_SOCKET": socket,
	} {
		if env[name] != want {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}
	for _, name := range []string{"VEIL_NER_MODEL_DIR", "VEIL_NER_ENTRY"} {
		if env[name] == "" {
			t.Errorf("%s is not set", name)
		}
	}
}

func TestModelServe_NoInheritedDescriptorReachesTheSidecar(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	_, _, out := serveEnv(t, true)
	// syscall.Open, unlike os.Open, leaves the descriptor inheritable,
	// like one veil itself inherited (VEIL_KEY_FD's fd 3).
	fd, err := syscall.Open(os.DevNull, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })

	script := `for fd in /proc/$$/fd/*; do echo "${fd##*/}"; done > "$1"`
	if code, _, stderr := runModelCmd(t, sidecar(script, out)...); code != 0 {
		t.Fatalf("exit %d (stderr %s), want 0", code, stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Fields(string(raw)) {
		n, err := strconv.Atoi(name)
		if err != nil {
			t.Fatalf("fd %q", name)
		}
		// The redirection to "$1" is the shell's own descriptor.
		if n > 2 && n == fd {
			t.Fatalf("fd %d reached the sidecar (open: %s)", fd, strings.Fields(string(raw)))
		}
	}
}

func TestModelServe_KillsASidecarThatIgnoresTermination(t *testing.T) {
	_, _, out := serveEnv(t, true)
	old := sidecarGrace
	sidecarGrace = 200 * time.Millisecond
	t.Cleanup(func() { sidecarGrace = old })
	script := `trap '' TERM; echo ready > "$1.ready"; while :; do sleep 0.05; done`

	done := make(chan int, 1)
	go func() {
		code, _, _ := runModelCmd(t, sidecar(script, out)...)
		done <- code
	}()
	waitFor(t, out+".ready")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != problem.ExitFailedClosed {
			t.Fatalf("exit %d, want %d for a sidecar that had to be killed", code, problem.ExitFailedClosed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve never killed a sidecar that ignores SIGTERM")
	}
}

const serveHelperEnv = "VEIL_TEST_SERVE_HELPER"

// TestModelServe_Helper is the serve process the next test kills.
func TestModelServe_Helper(t *testing.T) {
	pidFile := os.Getenv(serveHelperEnv)
	if pidFile == "" {
		t.Skip("run by TestModelServe_SidecarDiesWithServe")
	}
	_, _, _ = serveEnv(t, true)
	runModelCmd(t, sidecar(`echo $$ > "$1.tmp"; mv "$1.tmp" "$1"; exec sleep 600`, pidFile)...)
}

func TestModelServe_SidecarDiesWithServe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Pdeathsig is Linux only")
	}
	pidFile := filepath.Join(t.TempDir(), "pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestModelServe_Helper$", "-test.count=1") // #nosec G204 G702 -- the test binary itself
	helper.Env = append(os.Environ(), serveHelperEnv+"="+pidFile)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, pidFile)
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	// SIGKILL: serve gets no chance to forward anything.
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sidecar %d outlived the serve that started it", pid)
}
