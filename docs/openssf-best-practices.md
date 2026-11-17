# OpenSSF Best Practices badge: answers for every level

veil's entry is project **16829**: <https://www.bestpractices.dev/en/projects/16829>.
This document holds the answer for every passing, silver and gold criterion,
in the order the form shows them, ready to paste. Items only the owner can
make true are listed in [Owner-only items](#owner-only-items), with what each
one blocks.

Criteria IDs, order and wording come from the
[criteria list](https://www.bestpractices.dev/en/criteria/0) and its source,
[`docs/criteria.md`](https://github.com/coreinfrastructure/best-practices-badge/blob/main/docs/criteria.md)
(read 2026-11-17).

## Owner steps

1. Sign in at <https://www.bestpractices.dev/> with **"Log in with GitHub"**,
   using the account that owns `FullFran/veil`.
   (For a new project you would click **"Get your badge now!"** and enter the
   repository URL `https://github.com/FullFran/veil`; that is already done:
   the project is 16829.)
2. Open <https://www.bestpractices.dev/en/projects/16829/passing/edit>.
3. Go through the sections in order (Basics, Change Control, Reporting,
   Quality, Security, Analysis). For each criterion, pick the **Status** from
   the tables below and paste the **Justification** text into its box.
   Criteria marked **"after #N"** are only true once pull request #N is
   merged into `main`; fill them in after the merge.
4. Save each section (**"Save (and continue)"**), then **"Submit"** at the end.
   Repeat for silver (<https://www.bestpractices.dev/en/projects/16829/silver/edit>)
   and gold (<https://www.bestpractices.dev/en/projects/16829/gold/edit>) once
   the level below is achieved.
5. The README carries the badge (added with this document):

   ```markdown
   [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16829/badge)](https://www.bestpractices.dev/projects/16829)
   ```

   It shows "in progress" until every MUST is Met or N/A.

Optional: replace the generic notes of the existing v0.1.0 release with its
CHANGELOG section (later releases get it automatically from
`.github/workflows/release.yml`). Extract the `## [0.1.0]` section of
`CHANGELOG.md` into `notes.md` and run
`gh release edit v0.1.0 --repo FullFran/veil --notes-file notes.md`.

Four answers state facts only the owner can confirm (`report_responses`,
`enhancement_responses`, `know_secure_design`, `know_common_errors`); they are
marked "owner confirms". The justification text is written so it is true for
this repository today.

## Basics

| Criterion | Status | Justification (paste) |
|---|---|---|
| `homepage_url` | Met | https://github.com/FullFran/veil |
| `description_good` | Met | The README explains what veil does (a privacy guard for AI coding agents that blocks or pseudonymizes personal data before it leaves the machine) and what it cannot do: https://github.com/FullFran/veil#what-this-is |
| `interact` | Met | Obtain: prebuilt release binaries (https://github.com/FullFran/veil#prebuilt-binaries) or `go build ./cmd/veil`. Feedback: GitHub issues (https://github.com/FullFran/veil/issues). Contribute: https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md |
| `contribution` | Met | Contributions are pull requests against `main`, as described in https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md |
| `contribution_requirements` | Met | https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md lists the requirements: test first, the checks that must pass, Conventional Commits. |
| `floss_license` | Met | Apache-2.0. |
| `floss_license_osi` | Met | Apache-2.0 is an OSI-approved license. |
| `license_location` | Met | https://github.com/FullFran/veil/blob/main/LICENSE |
| `documentation_basics` | Met | The README documents installation on each host, configuration (policy, name catalog, environment variables), the pseudonym store and the limits: https://github.com/FullFran/veil#readme |
| `documentation_interface` | Met | The README documents the external interface: the commands (`veil claude-code`, `veil opencode`, `veil policy`, `veil store ...`), the environment variables, the policy schema, the evidence format, the failure types and the exit codes: https://github.com/FullFran/veil#failures |
| `sites_https` | Met | The project website, repository and release downloads are all on GitHub over HTTPS. |
| `discussion` | Met | GitHub issues and pull requests are searchable, addressable by URL and open to anyone with a GitHub account: https://github.com/FullFran/veil/issues |
| `english` | Met | Documentation, code, issues and pull requests are in English, and English bug reports and comments are accepted. |
| `maintained` | Met | The project is actively maintained: pull requests merged and issues opened in November 2026: https://github.com/FullFran/veil/pulls?q=is%3Apr |

## Change Control

| Criterion | Status | Justification (paste) |
|---|---|---|
| `repo_public` | Met | https://github.com/FullFran/veil |
| `repo_track` | Met | git tracks every change, its author and its date. |
| `repo_interim` | Met | Work between releases is merged into `main` through public pull requests. |
| `repo_distributed` | Met | git. |
| `version_unique` | Met | Each release has a unique `vMAJOR.MINOR.PATCH` tag; the release workflow refuses a tag that is not a version. |
| `version_semver` | Met | Releases follow Semantic Versioning 2.0.0 (`vMAJOR.MINOR.PATCH` tags). |
| `version_tags` | Met | Every release is a git tag: https://github.com/FullFran/veil/tags |
| `release_notes` | Met | Human-readable release notes for every release, in Keep a Changelog 1.1.0 format, with breaking changes marked: https://github.com/FullFran/veil/blob/main/CHANGELOG.md. The release workflow publishes each version's section as the GitHub release notes. |
| `release_notes_vulns` | Met | The "Security" subsection of each CHANGELOG version lists every publicly known vulnerability fixed in it, e.g. GO-2026-6218 under Unreleased: https://github.com/FullFran/veil/blob/main/CHANGELOG.md |

## Reporting

| Criterion | Status | Justification (paste) |
|---|---|---|
| `report_process` | Met | Bugs are reported as GitHub issues: https://github.com/FullFran/veil/issues |
| `report_tracker` | Met | GitHub issues. |
| `report_responses` | Met (owner confirms) | Every bug report in the last 12 months was acknowledged by the maintainer (https://github.com/FullFran/veil/issues?q=is%3Aissue). |
| `enhancement_responses` | Met (owner confirms) | Every enhancement request in the last 12 months got a response (https://github.com/FullFran/veil/issues?q=is%3Aissue). |
| `report_archive` | Met | https://github.com/FullFran/veil/issues?q=is%3Aissue |
| `vulnerability_report_process` | Met | https://github.com/FullFran/veil/blob/main/.github/SECURITY.md |
| `vulnerability_report_private` | Met | Private reports go through GitHub private vulnerability reporting (enabled): https://github.com/FullFran/veil/security/advisories/new, as described in https://github.com/FullFran/veil/blob/main/.github/SECURITY.md |
| `vulnerability_report_response` | N/A | No vulnerability reports were received in the last 6 months. |

## Quality

| Criterion | Status | Justification (paste) |
|---|---|---|
| `build` | Met | `go build ./cmd/veil` builds the binary; the release workflow builds every platform the same way: https://github.com/FullFran/veil/blob/main/.github/workflows/release.yml |
| `build_common_tools` | Met | The standard Go toolchain. |
| `build_floss_tools` | Met | Go and Node.js, both FLOSS. |
| `test` | Met | `go test ./...` and `node --test adapters/opencode/veil-plugin.test.mjs`, documented in https://github.com/FullFran/veil#development |
| `test_invocation` | Met | The standard `go test ./...`. |
| `test_most` | Met | Every detector, host adapter, the policy, the store, the evidence format and the failure types have tests; the CLI is tested end to end through its `run` entry point. |
| `test_continuous_integration` | Met | Every pull request and push to `main` runs the tests: https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml |
| `test_policy` | Met | New functionality must come with tests, written first: https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md |
| `tests_are_added` | Met | Recent feature pull requests add tests with the behaviour, e.g. https://github.com/FullFran/veil/pull/13, https://github.com/FullFran/veil/pull/17, https://github.com/FullFran/veil/pull/19 |
| `tests_documented_added` | Met | https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md (pull request instructions require tests). |
| `warnings` | Met | `go vet` and golangci-lint run on every pull request: https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml |
| `warnings_fixed` | Met | Any `go vet` or golangci-lint finding fails CI, so warnings are fixed before merge. |
| `warnings_strict` | Met | Warnings block merges (CI fails), and golangci-lint enables gosec, staticcheck and errcheck beyond the compiler. |

## Security

| Criterion | Status | Justification (paste) |
|---|---|---|
| `know_secure_design` | Met (owner confirms) | The maintainer applies secure-design principles throughout veil: fail closed on any error (unreadable input, policy, store or key), least privilege (owner-only store files, read-only CI tokens), economy of mechanism (one deletion path, one error registry), complete mediation of every hook event, and input validation of untrusted JSON. |
| `know_common_errors` | Met (owner confirms) | The maintainer knows the common errors for this kind of software and mitigates them: untrusted JSON input (strict decoding, `UseNumber`), path traversal (session ids are sanitized into file names inside the store directory), leaking secrets in logs or errors (problem details never carry input), race conditions (kernel file locks, race detector in CI), and supply-chain attacks (actions pinned by SHA, signed releases). |
| `crypto_published` | Met | The pseudonym store is encrypted with age v1 (C2SP age-encryption.org/v1: X25519, HKDF-SHA-256, ChaCha20-Poly1305); the policy digest is SHA-256. All are published, expert-reviewed algorithms. |
| `crypto_call` | Met | veil calls the `filippo.io/age` library and the Go standard library `crypto` packages; it implements no cryptographic primitive. |
| `crypto_floss` | Met | `filippo.io/age` (BSD-3-Clause) and the Go standard library (BSD-3-Clause) are FLOSS. |
| `crypto_keylength` | Met | X25519 keys (about 128-bit security) and 256-bit symmetric keys, above the NIST minimums through 2030; no smaller key length is supported. |
| `crypto_working` | Met | No broken algorithm (MD4, MD5, single DES, RC4, Dual_EC_DRBG) is used. |
| `crypto_weaknesses` | Met | No algorithm or mode with known serious weaknesses (SHA-1, CBC) is used. |
| `crypto_pfs` | N/A | veil implements no key agreement protocol for sessions; age encrypts files at rest. |
| `crypto_password_storage` | N/A | veil stores no passwords for authenticating external users. |
| `crypto_random` | Met | Keys are generated by `age.GenerateX25519Identity` and identifiers by `crypto/rand`, both cryptographically secure. |
| `delivery_mitm` | Met | Releases are delivered over HTTPS from GitHub, with `SHA256SUMS`, a Sigstore signature of it and SLSA build provenance: https://github.com/FullFran/veil#verifying-a-release |
| `delivery_unsigned` | Met | `SHA256SUMS` is fetched over HTTPS and is itself signed (keyless Sigstore); the README shows how to verify the signature before using the hashes: https://github.com/FullFran/veil#verifying-a-release |
| `vulnerabilities_fixed_60_days` | Met | There are no unpatched vulnerabilities of medium or higher severity publicly known for more than 60 days. govulncheck runs on every pull request. |
| `vulnerabilities_critical_fixed` | Met | Critical vulnerabilities are fixed as soon as they are reported; see https://github.com/FullFran/veil/blob/main/.github/SECURITY.md |
| `no_leaked_credentials` | Met | The repository holds no valid private credential. Release signing is keyless (Sigstore OIDC), so there is no signing key to leak; test keys are generated per test. |

## Analysis

| Criterion | Status | Justification (paste) |
|---|---|---|
| `static_analysis` | Met | Every pull request runs CodeQL (Go and GitHub Actions, security-extended queries; https://github.com/FullFran/veil/blob/main/.github/workflows/codeql.yml) and golangci-lint with gosec and staticcheck (https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml, https://github.com/FullFran/veil/blob/main/.golangci.yml); any finding fails the check, so it runs before every release. |
| `static_analysis_common_vulnerabilities` | Met | CodeQL security-extended and gosec look for common Go vulnerabilities (injection, path traversal, weak crypto, unchecked errors); govulncheck checks the code against the Go vulnerability database. |
| `static_analysis_fixed` | Met | Findings fail CI and are fixed or justified inline before merge, e.g. gosec's unchecked stdout write, which was a fail-open and is fixed in the pull request that added the analysers. |
| `static_analysis_often` | Met | Static analysis runs on every pull request and every push to `main`, and CodeQL also weekly. |
| `dynamic_analysis` | Met | Every pull request runs the full test suite under the Go race detector (`go test -race`): https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml |
| `dynamic_analysis_unsafe` | N/A | veil is written in Go, a memory-safe language, and is built with `CGO_ENABLED=0`. |
| `dynamic_analysis_enable_assertions` | Met | The race detector adds runtime checks to every memory access during the test run; they are not enabled in release builds. |
| `dynamic_analysis_fixed` | N/A | Dynamic analysis has found no medium or higher severity exploitable vulnerability. |

## Silver

Criteria that appear at passing with the same ID keep their passing answer
unless they are listed here (at silver some SHOULDs become MUSTs).

### Basics

| Criterion | Status | Justification (paste) |
|---|---|---|
| `achieve_passing` | Met (after passing is submitted) | The project has the passing badge. |
| `contribution_requirements` | Met | Coding standards, test and review requirements: https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md |
| `dco` | **Unmet (owner decision)** | Contributions are licensed inbound under Apache-2.0 section 5; no Developer Certificate of Origin sign-off is required yet. |
| `governance` | Met | Single-maintainer model, how decisions are made and recorded: https://github.com/FullFran/veil/blob/main/GOVERNANCE.md |
| `code_of_conduct` | Met | Contributor Covenant 2.1, with reporting and enforcement: https://github.com/FullFran/veil/blob/main/CODE_OF_CONDUCT.md |
| `roles_responsibilities` | Met | Roles (maintainer, contributor, reporter) and their tasks: https://github.com/FullFran/veil/blob/main/GOVERNANCE.md#roles |
| `access_continuity` | **Unmet (owner)** | Everything needed to continue is public and keyless (https://github.com/FullFran/veil/blob/main/GOVERNANCE.md#continuity), but only one person can administer the repository. |
| `bus_factor` | **Unmet (owner)** | One maintainer. |
| `documentation_roadmap` | Met | https://github.com/FullFran/veil/blob/main/ROADMAP.md |
| `documentation_architecture` | Met | https://github.com/FullFran/veil/blob/main/docs/architecture.md |
| `documentation_security` | Met | What veil does and does not protect: https://github.com/FullFran/veil#what-this-cannot-do, the threat model https://github.com/FullFran/veil/blob/main/docs/threat-model.md and the assurance case https://github.com/FullFran/veil/blob/main/docs/assurance-case.md |
| `documentation_quick_start` | Met | https://github.com/FullFran/veil#installing-on-claude-code and https://github.com/FullFran/veil#installing-on-opencode |
| `documentation_current` | Met | The review checklist requires README, CHANGELOG and threat model updates with each behaviour change (https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md#code-review), and `docs/threatmodel_test.go` fails CI when the threat model cites a test, file or line that no longer exists. |
| `documentation_achievements` | Met | The README shows the OpenSSF Best Practices and Scorecard badges: https://github.com/FullFran/veil#readme |
| `accessibility_best_practices` | N/A | veil has no user interface: it reads and writes JSON for other programs. The project sites are GitHub's. |
| `internationalization` | N/A | veil's output is machine-readable JSON with stable codes (`type`, `code`) that hosts present in their own language; it has no human-facing text to translate. |
| `sites_password_security` | N/A | The project sites are GitHub; the project stores no passwords. |

### Change Control

| Criterion | Status | Justification (paste) |
|---|---|---|
| `maintenance_or_update` | Met | Only the latest release is supported, and upgrading is replacing one binary; every change a host must act on is marked **Breaking** in https://github.com/FullFran/veil/blob/main/CHANGELOG.md with what to do, and old store formats are migrated on first use. See https://github.com/FullFran/veil/blob/main/docs/releasing.md#supported-versions (after #39). |

### Reporting

| Criterion | Status | Justification (paste) |
|---|---|---|
| `report_tracker` | Met | GitHub issues. |
| `vulnerability_report_credit` | N/A | No vulnerability reports were received in the last 12 months; the policy is to credit the reporter in the advisory and changelog: https://github.com/FullFran/veil/blob/main/.github/SECURITY.md |
| `vulnerability_response_process` | Met | https://github.com/FullFran/veil/blob/main/.github/SECURITY.md |

### Quality

| Criterion | Status | Justification (paste) |
|---|---|---|
| `coding_standards` | Met | Effective Go, Go Code Review Comments, gofmt and golangci-lint (`.golangci.yml`): https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md#coding-standards |
| `coding_standards_enforced` | Met | CI fails on `gofmt -l` output, `go vet` and golangci-lint findings: https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml |
| `build_standard_variables` | Met | The Go toolchain honors its standard variables (`GOFLAGS`, `GOOS`, `GOARCH`, `CGO_ENABLED`, and `CC`/`CGO_CFLAGS`/`CGO_LDFLAGS` when cgo is on); the project adds no build system on top. |
| `build_preserve_debug` | Met | `go build ./cmd/veil` keeps debugging information. Release binaries are stripped (`-s -w`) to reduce size; anyone can rebuild an unstripped binary from the tag. |
| `build_non_recursive` | Met | `go build`; there is no recursive make. |
| `build_repeatable` | Met (after #39) | Builds are reproducible: the same commit and Go version give the same bytes. https://github.com/FullFran/veil#reproducing-a-release-build |
| `installation_common` | Met | Install: download a release binary or `go install github.com/FullFran/veil/cmd/veil@latest`. Uninstall: delete the binary (and the hook entry), documented in https://github.com/FullFran/veil#installing-on-claude-code |
| `installation_standard_variables` | Met | `go install` honors `GOBIN` and `GOPATH`; prebuilt binaries go wherever the user puts them. |
| `installation_development_quick` | Met | `git clone` and `go test ./...` with the Go version in `go.mod`: https://github.com/FullFran/veil#development |
| `external_dependencies` | Met | `go.mod` and `go.sum` list every dependency with its version and checksum; the OpenCode plugin has none. |
| `dependency_monitoring` | Met | Dependabot (https://github.com/FullFran/veil/blob/main/.github/dependabot.yml), govulncheck on every pull request, and osv-scanner over every lockfile (after #34). |
| `updateable_reused_components` | Met | Dependencies are Go modules, updated with `go get` and proposed weekly by Dependabot; none is copied into the repository. |
| `interfaces_current` | Met | staticcheck (in golangci-lint) reports uses of deprecated APIs (SA1019) and fails CI. |
| `automated_integration_testing` | Met | Every pull request and push to `main` runs the full suite, including end-to-end tests through the `veil` command: https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml |
| `regression_tests_added50` | Met | Bug fixes add a regression test that fails without the fix (https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md#bug-fixes), e.g. https://github.com/FullFran/veil/pull/29 and https://github.com/FullFran/veil/pull/30 |
| `test_statement_coverage80` | Met | 89.6% statement coverage over the module (`go test -coverpkg=./...`), measured on every pull request; CI fails below 80%. |
| `test_policy_mandated` | Met | https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md (tests first, for every new behaviour). |
| `tests_documented_added` | Met | https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md |
| `warnings_strict` | Met | Any `go vet`, staticcheck or gosec finding fails CI. |

### Security

| Criterion | Status | Justification (paste) |
|---|---|---|
| `implement_secure_design` | Met | https://github.com/FullFran/veil/blob/main/docs/assurance-case.md#secure-design-principles-applied |
| `crypto_weaknesses` | Met | Only age v1 (X25519, HKDF-SHA-256, ChaCha20-Poly1305) and SHA-256. |
| `crypto_algorithm_agility` | Unmet | The store uses one algorithm suite, age v1 X25519. The store format is versioned, so a future suite can be added with a migration. |
| `crypto_credential_agility` | Met | The store key is never in code or configuration files: it comes from `VEIL_KEY_FD`, a systemd credential or the OS keyring, and can be replaced: https://github.com/FullFran/veil#key-sources |
| `crypto_used_network` | N/A | veil does not communicate over a network. |
| `crypto_tls12` | N/A | veil does not use TLS. |
| `crypto_certificate_verification` | N/A | veil does not use TLS. |
| `crypto_verification_private` | N/A | veil does not use TLS. |
| `signed_releases` | **Unmet until the next release (owner)** | The release workflow signs `SHA256SUMS` with Sigstore and attests SLSA provenance (https://github.com/FullFran/veil#verifying-a-release); v0.1.0 predates it, so it becomes Met when the next release is cut. |
| `version_tags_signed` | **Unmet (owner)** | Tags are not signed yet; https://github.com/FullFran/veil/blob/main/docs/releasing.md (after #39) recommends `git tag -s`. |
| `input_validation` | Met | Host JSON is decoded strictly and size-limited, the policy is validated against a JSON Schema, session ids are encoded before they name files, and every parser is fuzzed: https://github.com/FullFran/veil/blob/main/docs/assurance-case.md |
| `hardening` | Met | Memory-safe Go with `CGO_ENABLED=0`, owner-only store files, read-only CI tokens, fail-closed defaults, no network access. |
| `assurance_case` | Met | https://github.com/FullFran/veil/blob/main/docs/assurance-case.md |

### Analysis

| Criterion | Status | Justification (paste) |
|---|---|---|
| `static_analysis_common_vulnerabilities` | Met | CodeQL security-extended and gosec on every pull request. |
| `dynamic_analysis_unsafe` | N/A | Go, memory-safe, no cgo. |

## Gold

| Criterion | Status | Justification (paste) |
|---|---|---|
| `achieve_silver` | Unmet (needs silver) | |
| `bus_factor` | **Unmet (owner)** | One maintainer. |
| `contributors_unassociated` | **Unmet (owner)** | One significant contributor. |
| `copyright_per_file` | **Unmet (owner decision)** | Source files carry no copyright line; the copyright is in `NOTICE`. |
| `license_per_file` | **Unmet (owner decision)** | Source files carry no SPDX license line; the license is in `LICENSE`. |
| `repo_distributed` | Met | git. |
| `small_tasks` | **Unmet (owner)** | The `good first issue` label exists but no open issue carries it. |
| `require_2FA` | **Owner confirms** | GitHub requires 2FA for accounts that contribute code; the maintainer confirms it is on. |
| `secure_2FA` | **Owner confirms** | Met if the maintainer's GitHub 2FA is a passkey or security key, not SMS. |
| `code_review_standards` | Met | https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md#code-review |
| `two_person_review` | **Unmet (owner)** | Needs a second reviewer. |
| `build_reproducible` | Met (after #39) | https://github.com/FullFran/veil#reproducing-a-release-build |
| `test_invocation` | Met | `go test ./...` |
| `test_continuous_integration` | Met | https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml on every pull request and push to `main`. |
| `test_statement_coverage90` | Unmet | 89.6% statement coverage today (CI measures it on every pull request). |
| `test_branch_coverage80` | Unmet | Go's tooling measures statements, not branches; branch coverage is not measured. |
| `crypto_used_network` | N/A | No network communication. |
| `crypto_tls12` | N/A | No TLS. |
| `hardened_site` | Met | The repository and downloads are on github.com, which sends HSTS, `Content-Security-Policy`, `X-Content-Type-Options: nosniff` and `X-Frame-Options: deny`. |
| `security_review` | Met | The LINDDUN and STRIDE threat model of November 2026 reviews every trust boundary, with each threat's mitigation and test: https://github.com/FullFran/veil/blob/main/docs/threat-model.md |
| `hardening` | Met | As at silver. |
| `dynamic_analysis` | Met | Every pull request runs the race detector over the whole suite and fuzzes every parser (https://github.com/FullFran/veil/blob/main/.github/workflows/fuzz.yml, after #40). |
| `dynamic_analysis_enable_assertions` | Met | Fuzz targets assert invariants (no leaked value, fail-closed errors, deterministic digests); the race detector checks every memory access during tests. |

## Owner-only items

What only the owner can do, and what each one unlocks. Scorecard checks are
scored 0 to 10; the project's aggregate is their weighted average.

| Item | Unlocks |
|---|---|
| Submit the passing answers, then silver | The badge's level; Scorecard `CII-Best-Practices` goes 2 (in progress) → 5 (passing) → 7 (silver) → 10 (gold) |
| Branch protection on `main` (require pull requests and the CI checks, no force push) | Scorecard `Branch-Protection` |
| A second maintainer with admin access who reviews pull requests | Silver `access_continuity` and `bus_factor`; gold `bus_factor`, `two_person_review`, `contributors_unassociated`; Scorecard `Code-Review` and `Contributors` |
| Cut the next release with the current workflow | Silver `signed_releases`; Scorecard `Signed-Releases` (needs signatures and provenance on recent releases) |
| Sign tags (`git tag -s`) | Silver `version_tags_signed` |
| Adopt the DCO (`Signed-off-by` on commits, checked in CI) | Silver `dco` |
| SPDX and copyright header in every source file | Gold `copyright_per_file`, `license_per_file` |
| Label small tasks `good first issue` | Gold `small_tasks` |
| Confirm 2FA with a passkey or security key | Gold `require_2FA`, `secure_2FA` |
| Raise coverage over 90% and measure branch coverage | Gold `test_statement_coverage90`, `test_branch_coverage80` |
