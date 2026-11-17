// Package supplychain_test checks the release supply chain controls that
// docs/threat-model.md claims, by reading the GitHub Actions workflows
// themselves: a control that only lives in a YAML file can be dropped by an
// edit nobody notices, and these tests make that edit fail CI.
package supplychain_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const workflowsDir = "../../.github/workflows"

// workflows returns every workflow file and its contents.
func workflows(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(workflowsDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no workflow found under %s", workflowsDir)
	}
	out := map[string]string{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = string(raw)
	}
	return out
}

var (
	usesLine  = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)`)
	pinnedRef = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
)

// TestWorkflows_PinEveryActionByCommitSHA: a tag or branch can be moved to
// other code after review (OpenSSF Scorecard Pinned-Dependencies), a full
// commit SHA cannot. Local actions (./...) are part of the repository.
func TestWorkflows_PinEveryActionByCommitSHA(t *testing.T) {
	for name, body := range workflows(t) {
		for _, m := range usesLine.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "./") {
				continue
			}
			if !pinnedRef.MatchString(ref) {
				t.Errorf("%s: action %q is not pinned to a 40-hex commit SHA", name, ref)
			}
		}
	}
}

// TestWorkflows_DefaultTokenIsReadOnly: every workflow sets a top-level
// permissions block that only reads (OpenSSF Scorecard Token-Permissions);
// a job that needs to write asks for it at job level.
func TestWorkflows_DefaultTokenIsReadOnly(t *testing.T) {
	for name, body := range workflows(t) {
		top := topLevelPermissions(body)
		switch {
		case top == nil:
			t.Errorf("%s: no top-level permissions block", name)
		case len(top) == 1 && (top[0] == "read-all" || top[0] == "contents: read"):
		default:
			t.Errorf("%s: top-level permissions %q, want read-all or only contents: read", name, top)
		}
	}
}

// topLevelPermissions returns the value of the workflow's top-level
// permissions key: its inline value, or the lines of its block.
func topLevelPermissions(body string) []string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "permissions:") {
			continue
		}
		if inline := strings.TrimSpace(strings.TrimPrefix(line, "permissions:")); inline != "" {
			return []string{inline}
		}
		var block []string
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !strings.HasPrefix(next, " ") {
				break
			}
			block = append(block, trimmed)
		}
		return block
	}
	return nil
}

// TestRelease_VerifiesSignatureAndProvenanceBeforePublishing: the release
// job checks the cosign signature of SHA256SUMS and the SLSA provenance of
// every asset, refusing self-hosted runners, before the step that publishes
// them, so a release never ships an artifact its own verification rejects.
func TestRelease_VerifiesSignatureAndProvenanceBeforePublishing(t *testing.T) {
	body, ok := workflows(t)["release.yml"]
	if !ok {
		t.Fatal("release.yml not found")
	}
	publish := strings.Index(body, "gh release create")
	if publish < 0 {
		t.Fatal("release.yml has no publishing step (gh release create)")
	}
	for _, check := range []string{
		"actions/attest@",
		"cosign sign-blob",
		"cosign verify-blob SHA256SUMS",
		"sha256sum --check SHA256SUMS",
		"gh attestation verify",
		"--predicate-type https://slsa.dev/provenance/v1",
		"--deny-self-hosted-runners",
	} {
		at := strings.Index(body, check)
		if at < 0 {
			t.Errorf("release.yml does not run %q", check)
			continue
		}
		if at > publish {
			t.Errorf("release.yml runs %q after it publishes", check)
		}
	}
}

// TestRelease_GoReleaserOnlyBuilds: release.yml builds the binaries with
// GoReleaser (the packaging step OpenSSF Scorecard detects) BEFORE the
// provenance attestation, so every binary is covered by it, and
// .goreleaser.yaml never publishes, signs or checksums anything itself: the
// one publishing path stays the verified gh release step.
func TestRelease_GoReleaserOnlyBuilds(t *testing.T) {
	body, ok := workflows(t)["release.yml"]
	if !ok {
		t.Fatal("release.yml not found")
	}
	build := strings.Index(body, "goreleaser/goreleaser-action@")
	attest := strings.Index(body, "actions/attest@")
	if build < 0 || attest < 0 || build > attest {
		t.Fatalf("release.yml goreleaser at %d, attest at %d: want GoReleaser to build before the attestation", build, attest)
	}

	raw, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config := string(raw)
	for _, section := range []string{"release", "checksum", "changelog"} {
		if !regexp.MustCompile(`(?m)^` + section + `:\n\s+disable: true$`).MatchString(config) {
			t.Errorf(".goreleaser.yaml: %s is not disabled", section)
		}
	}
	for _, forbidden := range []string{"signs:", "sboms:", "dockers:", "brews:", "nfpms:", "publishers:", "blobs:"} {
		if strings.Contains(config, forbidden) {
			t.Errorf(".goreleaser.yaml has %q: signing and publishing belong to release.yml", forbidden)
		}
	}
	// Reproducible: no build path or file time in the binaries.
	for _, setting := range []string{"-trimpath", "mod_timestamp: \"{{ .CommitTimestamp }}\"", "CGO_ENABLED=0"} {
		if !strings.Contains(config, setting) {
			t.Errorf(".goreleaser.yaml does not set %s", setting)
		}
	}
}

// TestCI_EnforcesStatementCoverage: ci.yml measures statement coverage over
// the whole module on every pull request and fails below 80% (OpenSSF Best
// Practices silver, test_statement_coverage80).
func TestCI_EnforcesStatementCoverage(t *testing.T) {
	body, ok := workflows(t)["ci.yml"]
	if !ok {
		t.Fatal("ci.yml not found")
	}
	for _, want := range []string{"-coverpkg=./...", "-coverprofile=", "go tool cover -func", "MIN_COVERAGE: \"80\""} {
		if !strings.Contains(body, want) {
			t.Errorf("ci.yml does not contain %q", want)
		}
	}
}
