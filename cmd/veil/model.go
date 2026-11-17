package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/FullFran/veil/internal/ner"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
)

// modelHTTPClient builds the client `veil model pull` downloads with;
// tests replace it to trust their TLS server.
var modelHTTPClient = ner.HTTPClient

// modelErrors maps each model catalog and cache sentinel to its code.
var modelErrors = []struct {
	err  error
	code problem.Code
}{
	{ner.ErrModelUnknown, problem.ModelUnknown},
	{ner.ErrCatalogInvalid, problem.ModelCatalogInvalid},
	{ner.ErrModelMissing, problem.ModelMissing},
	{ner.ErrDigestMismatch, problem.ModelDigestMismatch},
	{ner.ErrLicenseNotAccepted, problem.ModelLicenseNotAccepted},
	{ner.ErrDownload, problem.ModelDownload},
}

// runModel implements the `veil model` commands, which manage the local
// NER models of the catalog:
//
//	veil model list
//	veil model pull <id> --accept-license <SPDX id>
//	veil model verify [<id>]
//	veil model serve <command> [<arg> ...]
//
// list prints one JSON line per catalog entry. pull prints the model's
// licence first, then downloads it only if --accept-license names exactly
// that SPDX id, and prints where it is. verify re-hashes every cached
// file of <id>, or of the model the policy selects. serve verifies the
// selected model and runs <command>, the sidecar, in the foreground with
// its socket, model directory and catalog entry in its environment, and
// exits with its exit code. A failure is one
// problem line on stderr and exit 1; bad arguments exit 2.
func runModel(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	catalog, err := ner.LoadCatalog(os.Getenv(ner.CatalogEnvVar))
	if err != nil {
		return failModel(stderr, err)
	}
	root, err := ner.CacheRoot()
	if err != nil {
		return failModel(stderr, err)
	}
	switch subcommand, rest := args[0], args[1:]; subcommand {
	case "list":
		if len(rest) != 0 {
			return usage(stderr)
		}
		return listModels(stdout, stderr, catalog, root)
	case "pull":
		id, accepted, ok := pullArgs(rest)
		if !ok {
			return usage(stderr)
		}
		return pullModel(stdout, stderr, catalog, root, id, accepted)
	case "serve":
		if len(rest) == 0 {
			return usage(stderr)
		}
		return serveModel(stdout, stderr, catalog, root, rest[0], rest[1:])
	case "verify":
		if len(rest) > 1 {
			return usage(stderr)
		}
		id := ""
		if len(rest) == 1 {
			id = rest[0]
		}
		return verifyModel(stdout, stderr, catalog, root, id)
	default:
		return usage(stderr)
	}
}

type modelLine struct {
	ID        string     `json:"id"`
	Runtime   string     `json:"runtime"`
	License   string     `json:"license"`
	Languages []string   `json:"languages"`
	Bytes     int64      `json:"bytes"`
	Cost      *ner.Cost  `json:"cost,omitempty"`
	Source    ner.Source `json:"source"`
	Present   bool       `json:"present"`
}

func describe(e ner.Entry, root string) modelLine {
	var size int64
	for _, f := range e.Files {
		size += f.Size
	}
	return modelLine{
		ID: e.ID, Runtime: e.Runtime, License: e.License, Languages: e.Languages,
		Bytes: size, Cost: e.Cost, Source: e.Source,
		Present: ner.Present(ner.ModelDir(root, e), e),
	}
}

func listModels(stdout, stderr io.Writer, catalog *ner.Catalog, root string) int {
	for _, e := range catalog.Entries() {
		if code := answer(stdout, stderr, describe(e, root)); code != problem.ExitDecision {
			return code
		}
	}
	return problem.ExitDecision
}

// pullArgs reads `<id> --accept-license <SPDX>` in either order, and
// `--accept-license=<SPDX>`.
func pullArgs(args []string) (id, accepted string, ok bool) {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--accept-license" && i+1 < len(args):
			accepted = args[i+1]
			i++
		case strings.HasPrefix(a, "--accept-license="):
			accepted = strings.TrimPrefix(a, "--accept-license=")
		case strings.HasPrefix(a, "-") || id != "":
			return "", "", false
		default:
			id = a
		}
	}
	return id, accepted, id != ""
}

type cachedLine struct {
	ID       string `json:"id"`
	Dir      string `json:"dir"`
	Verified bool   `json:"verified"`
}

func pullModel(stdout, stderr io.Writer, catalog *ner.Catalog, root, id, accepted string) int {
	entry, err := catalog.Lookup(id)
	if err != nil {
		return failModel(stderr, err)
	}
	// The licence is printed before anything is downloaded, accepted or not.
	if code := answer(stdout, stderr, describe(entry, root)); code != problem.ExitDecision {
		return code
	}
	if err := ner.AcceptLicense(entry, accepted); err != nil {
		return failModel(stderr, err)
	}
	dir := ner.ModelDir(root, entry)
	if err := ner.Pull(context.Background(), modelHTTPClient(), dir, entry); err != nil {
		return failModel(stderr, err)
	}
	return answer(stdout, stderr, cachedLine{ID: entry.ID, Dir: dir, Verified: true})
}

func verifyModel(stdout, stderr io.Writer, catalog *ner.Catalog, root, id string) int {
	if id == "" {
		selected, ok, err := selectedModel()
		if err != nil {
			return failPolicy(stderr, err)
		}
		if !ok {
			return usage(stderr)
		}
		id = selected
	}
	entry, err := catalog.Lookup(id)
	if err != nil {
		return failModel(stderr, err)
	}
	dir := ner.ModelDir(root, entry)
	if err := ner.Verify(dir, entry); err != nil {
		return failModel(stderr, err)
	}
	return answer(stdout, stderr, cachedLine{ID: entry.ID, Dir: dir, Verified: true})
}

// selectedModel is the model id the policy (or VEIL_NER_MODEL) selects,
// and false when the policy does not enable ner.
func selectedModel() (string, bool, error) {
	p, err := policy.FromEnv()
	if err != nil {
		return "", false, err
	}
	rule, ok, err := p.NER(os.Getenv(ner.ModelEnvVar))
	return rule.Model, ok, err
}

func failPolicy(stderr io.Writer, err error) int {
	_ = problem.Write(stderr, problem.New(classifyPolicyError(err)))
	return problem.ExitFailedClosed
}

func failModel(stderr io.Writer, err error) int {
	code := problem.Internal
	for _, m := range modelErrors {
		if errors.Is(err, m.err) {
			code = m.code
			break
		}
	}
	_ = problem.Write(stderr, problem.New(code))
	return problem.ExitFailedClosed
}

// Environment of the sidecar `veil model serve` runs.
const (
	sidecarModelDirEnv = "VEIL_NER_MODEL_DIR"
	sidecarEntryEnv    = "VEIL_NER_ENTRY"
)

// serveModel verifies the selected model and runs the sidecar command
// with VEIL_NER_SOCKET, VEIL_NER_MODEL_DIR and VEIL_NER_ENTRY (the
// entry's canonical JSON, whose SHA-256 is the entry digest the sidecar
// reports). It never detaches: the sidecar lives as long as this process.
func serveModel(stdout, stderr io.Writer, catalog *ner.Catalog, root, command string, args []string) int {
	id, ok, err := selectedModel()
	if err != nil {
		return failPolicy(stderr, err)
	}
	if !ok {
		return usage(stderr)
	}
	entry, err := catalog.Lookup(id)
	if err != nil {
		return failModel(stderr, err)
	}
	dir := ner.ModelDir(root, entry)
	if err := ner.Verify(dir, entry); err != nil {
		return failModel(stderr, err)
	}
	socket := ner.SocketPath()
	if socket == "" {
		return failNER(stderr)
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return failNER(stderr)
	}
	// Only stdin, stdout and stderr reach the sidecar: a descriptor veil
	// inherited (VEIL_KEY_FD's) is closed in it.
	if err := closeInheritedDescriptors(); err != nil {
		return failNER(stderr)
	}
	cmd := exec.Command(command, args...) // #nosec G204 G702 -- the operator names the sidecar command to run
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = sidecarEnv(os.Environ(),
		ner.SocketEnvVar+"="+socket,
		sidecarModelDirEnv+"="+dir,
		sidecarEntryEnv+"="+string(entry.Canonical()),
	)
	cmd.SysProcAttr = sidecarProcAttr()
	// SIGINT and SIGTERM (Ctrl-C, systemd, kill) go to the sidecar, which
	// removes its socket and exits; serve then exits with its code. A
	// sidecar still running sidecarGrace later is killed.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return failNER(stderr)
	}
	exited := make(chan struct{})
	go func() {
		var kill <-chan time.Time
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
				if kill == nil {
					kill = time.After(sidecarGrace)
				}
			case <-kill:
				_ = cmd.Process.Kill()
			case <-exited:
				return
			}
		}
	}()
	err = cmd.Wait()
	close(exited)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return problem.ExitDecision
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		return exit.ExitCode()
	default:
		return failNER(stderr)
	}
}

// sidecarEnv is the sidecar's environment: the variables of environ it
// needs to run (PATH, HOME, TMPDIR, LANG, LC_*, XDG_*) and then extra.
// Nothing else veil was given (keys, policy, credentials) reaches it.
func sidecarEnv(environ []string, extra ...string) []string {
	var env []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "PATH", name == "HOME", name == "TMPDIR", name == "LANG",
			strings.HasPrefix(name, "LC_"), strings.HasPrefix(name, "XDG_"):
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// sidecarGrace is how long a sidecar has to exit after serve forwards
// SIGINT or SIGTERM to it, before serve kills it.
var sidecarGrace = 10 * time.Second

// failNER reports a sidecar that could not be started.
func failNER(stderr io.Writer) int {
	_ = problem.Write(stderr, problem.New(problem.NERUnavailable))
	return problem.ExitFailedClosed
}
