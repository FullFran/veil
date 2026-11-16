# OpenSSF Best Practices badge: prepared answers (passing level)

This document prepares the answers for the
[OpenSSF Best Practices badge](https://www.bestpractices.dev/) at the
**passing** level. Applying is the repository owner's job: the badge entry
is created and edited by a logged-in maintainer on bestpractices.dev, and some
criteria depend on repository settings only the owner can change.

Criteria IDs and levels come from the
[passing criteria](https://github.com/ossf/best-practices-badge/blob/main/docs/criteria.md)
(read 2026-11-16).

## What the owner must do

1. **Enable private vulnerability reporting** (Settings > Code security >
   Private vulnerability reporting). It is off today, and
   `.github/SECURITY.md` relies on it (`vulnerability_report_private`).
2. **Write human release notes for each release** (`release_notes`, MUST).
   The release workflow's notes ("Prebuilt veil binaries ... for vX") are not
   a summary of changes. Edit each release's notes, or pass `--notes-file`
   from a changelog in a later change to `release.yml`.
3. **Add a SAST tool before claiming `static_analysis` Met** (see below).
   CodeQL for Go, or `govulncheck` plus `staticcheck` in CI, would close it.
4. **Sign in at <https://www.bestpractices.dev/en/projects/new>** with the
   GitHub account that owns `FullFran/veil`, enter
   `https://github.com/FullFran/veil`, and fill in the answers below.
5. **Add the badge to the README** with the project number the site assigns:
   `[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<N>/badge)](https://www.bestpractices.dev/projects/<N>)`.

## Answers

Status: **Met**, **Unmet** (blocks the badge until fixed), **N/A**, or
**Owner** (depends on a setting or practice the owner confirms).

### Basics

| Criterion | Level | Status | Justification / URL |
|---|---|---|---|
| `description_good` | MUST | Met | README "What this is": <https://github.com/FullFran/veil#what-this-is> |
| `interact` | MUST | Met | Obtain: README "Prebuilt binaries"; feedback: GitHub issues; contribute: `.github/CONTRIBUTING.md` |
| `contribution` | MUST | Met | <https://github.com/FullFran/veil/blob/main/.github/CONTRIBUTING.md> (pull requests against `main`) |
| `contribution_requirements` | SHOULD | Met | Same file: test-first, checks, Conventional Commits |
| `floss_license` | MUST | Met | Apache-2.0 |
| `floss_license_osi` | SUGGESTED | Met | Apache-2.0 is OSI approved |
| `license_location` | MUST | Met | <https://github.com/FullFran/veil/blob/main/LICENSE> |
| `documentation_basics` | MUST | Met | README: install on each host, configuration, limits |
| `documentation_interface` | MUST | Met | README: commands (`veil claude-code`, `veil opencode`), environment variables table, plugin error codes |
| `sites_https` | MUST | Met | GitHub only (HTTPS) |
| `discussion` | MUST | Met | GitHub issues and pull requests |
| `english` | SHOULD | Met | Docs, issues and code in English |
| `maintained` | MUST | Met | Active commits and issues in 2026 |

### Change control

| Criterion | Level | Status | Justification / URL |
|---|---|---|---|
| `repo_public` | MUST | Met | <https://github.com/FullFran/veil> |
| `repo_track` | MUST | Met | git |
| `repo_interim` | MUST | Met | Work happens in pull requests between releases |
| `repo_distributed` | SUGGESTED | Met | git |
| `version_unique` | MUST | Met | Tags `vMAJOR.MINOR.PATCH`; the release workflow refuses a non-version tag |
| `version_semver` | SUGGESTED | Met | SemVer tags |
| `version_tags` | SUGGESTED | Met | Git tags per release |
| `release_notes` | MUST | **Unmet** | See "What the owner must do", item 2 |
| `release_notes_vulns` | MUST | N/A | No publicly known vulnerability with a CVE has been fixed yet |

### Reporting

| Criterion | Level | Status | Justification / URL |
|---|---|---|---|
| `report_process` | MUST | Met | GitHub issues; `.github/CONTRIBUTING.md` |
| `report_tracker` | SHOULD | Met | GitHub issues |
| `report_responses` | MUST | Owner | Owner confirms most bug reports in the last 2-12 months were acknowledged |
| `enhancement_responses` | SHOULD | Owner | Same, for enhancement requests |
| `report_archive` | MUST | Met | <https://github.com/FullFran/veil/issues?q=is%3Aissue> |
| `vulnerability_report_process` | MUST | Met | <https://github.com/FullFran/veil/blob/main/.github/SECURITY.md> |
| `vulnerability_report_private` | MUST | **Owner** | Met once private vulnerability reporting is enabled (item 1) |
| `vulnerability_report_response` | MUST | N/A | No vulnerability reports received in the last 6 months (owner confirms) |

### Quality

| Criterion | Level | Status | Justification / URL |
|---|---|---|---|
| `build` | MUST | Met | `go build ./cmd/veil` |
| `build_common_tools` | SUGGESTED | Met | Go toolchain |
| `build_floss_tools` | SHOULD | Met | Go, Node.js |
| `test` | MUST | Met | `go test ./...`, `node --test adapters/opencode/veil-plugin.test.mjs` (README "Development") |
| `test_invocation` | SHOULD | Met | Standard `go test` |
| `test_most` | SUGGESTED | Met | Every detector, adapter and the capability matrix has tests |
| `test_continuous_integration` | SUGGESTED | Met | `.github/workflows/ci.yml` on every pull request |
| `test_policy` | MUST | Met | `.github/CONTRIBUTING.md` step 3 |
| `tests_are_added` | MUST | Met | Recent feature PRs (#4) add tests with the behaviour |
| `tests_documented_added` | SUGGESTED | Met | `.github/CONTRIBUTING.md` step 3 |
| `warnings` | MUST | Met | `go vet ./...` and `gofmt -l` in CI |
| `warnings_fixed` | MUST | Met | CI fails on any `go vet` finding |
| `warnings_strict` | SUGGESTED | Met | `go vet` findings block merges |

### Security

| Criterion | Level | Status | Justification / URL |
|---|---|---|---|
| `know_secure_design` | MUST | Owner | Owner states their secure-design knowledge (fail-closed design, least privilege, explicit capability errors) |
| `know_common_errors` | MUST | Owner | Owner states the common errors they mitigate (input parsing of untrusted JSON, fail-closed on unreadable input, no secrets in logs) |
| `crypto_published` .. `crypto_random` | MUST/SHOULD | N/A | veil's own code implements and calls no cryptography (no `crypto/*` imports outside tests); detectors use checksums (mod-23, mod-97) for validation, not security |
| `delivery_mitm` | MUST | Met | Delivered over HTTPS from GitHub releases; `SHA256SUMS`, Sigstore signature and SLSA provenance (README "Verifying a release") |
| `delivery_unsigned` | MUST NOT | Met | Hashes are fetched over HTTPS and signed; README tells hosts to verify provenance before pinning |
| `vulnerabilities_fixed_60_days` | MUST | Met | No unpatched vulnerability of medium or higher severity publicly known for more than 60 days (owner confirms) |
| `vulnerabilities_critical_fixed` | SHOULD | Met | Same |
| `no_leaked_credentials` | MUST NOT | Met | No credentials in the repository; release signing is keyless (Sigstore OIDC), so there is no signing key to leak |

### Analysis

| Criterion | Level | Status | Justification / URL |
|---|---|---|---|
| `static_analysis` | MUST | **Unmet** | `go vet` counts for `warnings`; the archsieve gate is structural, not a code analyser. Add CodeQL or `staticcheck`/`govulncheck` (item 3) |
| `static_analysis_common_vulnerabilities` | SUGGESTED | Unmet | Same fix (CodeQL or `govulncheck`) |
| `static_analysis_fixed` | MUST | N/A until a tool runs | |
| `static_analysis_often` | SUGGESTED | Met once added to CI | |
| `dynamic_analysis` | SUGGESTED | Unmet | Go fuzz tests on the detectors would meet it |
| `dynamic_analysis_unsafe` | SUGGESTED | N/A | Go is memory safe |
| `dynamic_analysis_enable_assertions` | SUGGESTED | Unmet | |
| `dynamic_analysis_fixed` | MUST | N/A | No dynamic analysis findings |
