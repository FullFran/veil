# OpenSSF Best Practices badge: answers for the passing level

veil's entry is project **16829**: <https://www.bestpractices.dev/en/projects/16829>.
This document holds the final answer for every passing criterion, in the order
the form shows them, ready to paste.

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
   Criteria marked **"after PR merge"** are only true once the pull request
   that added this version of the document is merged into `main`; fill them
   in after the merge.
4. Save each section (**"Save (and continue)"**), then **"Submit"** at the end.
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
| `release_notes` | Met **(after PR merge)** | Human-readable release notes for every release, in Keep a Changelog 1.1.0 format, with breaking changes marked: https://github.com/FullFran/veil/blob/main/CHANGELOG.md. The release workflow publishes each version's section as the GitHub release notes. |
| `release_notes_vulns` | Met **(after PR merge)** | The "Security" subsection of each CHANGELOG version lists every publicly known vulnerability fixed in it, e.g. GO-2026-6218 under Unreleased: https://github.com/FullFran/veil/blob/main/CHANGELOG.md |

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
| `static_analysis` | Met **(after PR merge)** | Every pull request runs CodeQL (Go and GitHub Actions, security-extended queries; https://github.com/FullFran/veil/blob/main/.github/workflows/codeql.yml) and golangci-lint with gosec and staticcheck (https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml, https://github.com/FullFran/veil/blob/main/.golangci.yml); any finding fails the check, so it runs before every release. |
| `static_analysis_common_vulnerabilities` | Met **(after PR merge)** | CodeQL security-extended and gosec look for common Go vulnerabilities (injection, path traversal, weak crypto, unchecked errors); govulncheck checks the code against the Go vulnerability database. |
| `static_analysis_fixed` | Met **(after PR merge)** | Findings fail CI and are fixed or justified inline before merge, e.g. gosec's unchecked stdout write, which was a fail-open and is fixed in the pull request that added the analysers. |
| `static_analysis_often` | Met **(after PR merge)** | Static analysis runs on every pull request and every push to `main`, and CodeQL also weekly. |
| `dynamic_analysis` | Met **(after PR merge)** | Every pull request runs the full test suite under the Go race detector (`go test -race`): https://github.com/FullFran/veil/blob/main/.github/workflows/ci.yml |
| `dynamic_analysis_unsafe` | N/A | veil is written in Go, a memory-safe language, and is built with `CGO_ENABLED=0`. |
| `dynamic_analysis_enable_assertions` | Met **(after PR merge)** | The race detector adds runtime checks to every memory access during the test run; they are not enabled in release builds. |
| `dynamic_analysis_fixed` | N/A | Dynamic analysis has found no medium or higher severity exploitable vulnerability. |
