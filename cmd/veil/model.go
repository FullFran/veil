package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

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
//
// list prints one JSON line per catalog entry. pull prints the model's
// licence first, then downloads it only if --accept-license names exactly
// that SPDX id, and prints where it is. verify re-hashes every cached
// file of <id>, or of the model the policy selects. A failure is one
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
