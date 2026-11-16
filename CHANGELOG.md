# Changelog

All notable changes to veil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is 0, a minor version may break compatibility; every
such change is marked **Breaking** with what a host must do.

Each release's notes on GitHub are its section of this file
(`.github/workflows/release.yml`). Before tagging `vX.Y.Z`, rename
`[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD` and add a new empty `[Unreleased]`.

## [Unreleased]

### Added

- Failures are reported as RFC 9457 problem details: one JSON line on stderr
  with a stable `type` (`tag:` URI) and `code`, and never a detected value,
  path or session id (#13).
- Declarative, versioned policy: `VEIL_POLICY=<file>` validated against a
  JSON Schema 2020-12 document, with an embedded default equal to the previous
  behaviour; `veil policy [file]` prints its `sha256:` digest over the RFC 8785
  canonical form. New codes `VEIL_POLICY_UNREADABLE` and `VEIL_POLICY_INVALID`
  (#15).
- Synthetic Spanish evaluation corpus (`testdata/corpus/es/v1`), the
  `veil-eval` command and a recall and latency baseline enforced by
  `go test ./...` (#15).
- Pseudonym store commands `veil store reveal <session>` and
  `veil store forget <session> [...]` (#17), `veil store sweep` and
  `veil store find --value <v|->` (#19).
- Store key sources: `VEIL_KEY_FD`, the systemd credential `veil-store-key`
  and the OS keyring (#17).
- Session retention: an optional `store.ttl` (ISO 8601 duration) in the
  policy, swept at every start and by `veil store sweep`. No TTL deletes
  nothing (#19).
- Decision evidence with no personal data: one CloudEvents 1.0.2 record per
  decision carrying an OCSF 1.9.0 Data Security Finding (class 2006) and W3C
  DPV categories. `veil opencode` adds an `evidence` member to its answer;
  `VEIL_EVIDENCE_FILE` appends JSONL; `VEIL_CATALOG_REVISION` labels the
  catalog. New codes `VEIL_EVIDENCE_WRITE` and `VEIL_CATALOG_REVISION_INVALID`
  (#18).
- Release assets: prebuilt binaries for Linux, macOS and Windows (amd64,
  arm64), the OpenCode plugin and `SHA256SUMS` (#2), plus SLSA v1 build
  provenance (`veil.intoto.jsonl`) and a keyless Sigstore signature of
  `SHA256SUMS` (#14).
- Pull request CI (gofmt, vet, tests, plugin test), an archsieve architecture
  gate, OpenSSF Scorecard and Dependabot (#14); static analysis with CodeQL,
  golangci-lint (gosec) and govulncheck.
- OpenCode plugin: `VEIL_TIMEOUT_MS` (default 30000) and a 64 MiB output
  limit (#4).

### Changed

- **Breaking (rewrite args shape):** a tool-call `rewrite` keeps the original
  JSON types in `args` (OpenCode) and `updatedInput` (Claude Code); arrays
  stay arrays and numbers and booleans keep their type unless rewritten.
  Hosts that expected every value as a string must read typed values (#4).
- **Breaking (error format):** failures are no longer `veil: ...` text on
  stderr. Hosts must parse the problem JSON line and branch on `type` or
  `code`, never on text. OpenCode plugin errors carry a `code`
  (`VEIL_OUTPUT_TOO_LARGE`, `VEIL_TIMEOUT`, `VEIL_UNAVAILABLE`) (#4, #13).
- **Breaking (exit codes):** the exit code carries only the class: 0 decision
  (allow, deny or rewrite), 2 usage, 1 failed closed; `veil claude-code` fails
  closed with 2, because Claude Code treats other nonzero codes as
  non-blocking. An OpenCode deny now exits 0 with the action on stdout. Hosts
  that treated exit 1 as deny must read the action instead (#13).
- **Breaking (store format):** the pseudonym store is now one age-encrypted
  file per session (`<session>.age`, format v2) and needs a key from one of
  the key sources; with none it fails closed with `VEIL_STORE_KEY_MISSING`. A
  v1 plaintext `<session>.json` is migrated on first access and removed (#17).
  Each session also keeps a `<session>.ctr` counters file so marker numbers
  are never reused, and a session removed without readable counters is
  retired (`VEIL_SESSION_RETIRED`; the host must use a new session id) (#19).
- **Breaking (store locks):** session locks are now kernel locks (`flock`,
  `LockFileEx`) that are released when the holder dies. Do not run two veil
  versions on the same store at once: old and new locks do not exclude each
  other (#19).
- The lock timeout reports `VEIL_STORE_LOCKED` instead of `VEIL_INTERNAL`
  (#17).
- Detectors run in a fixed order whatever order the policy lists them in
  (#15).
- Releases are built with the Go 1.26.11 toolchain (`toolchain` directive in
  `go.mod`).

### Fixed

- Catalog names are cut at rune offsets: inputs such as `¿Ana García` no
  longer leak in clear or panic on multibyte runes (#4).
- IBAN, DNI/NIE and Spanish phone numbers written with separators are
  detected, and share a token with the compact form (#4).
- A dotted top-level tool-argument key no longer hides a nested key with the
  same path from the scan, and JSON numbers keep full precision (#4).
- A failure on the OpenCode `tool.execute.after` hook withholds the tool
  output instead of passing it through (#13).
- Detector misses recorded by the Spanish corpus baseline: separated IBANs of
  any ISO 13616 country (SWIFT IBAN Registry length and mod-97), Unicode email
  addresses, `(+34)` / `(0034)` and dot-separated phone numbers, and catalog
  names joined by a hyphen or apostrophe (`García-López`, `O'Neill`) (#21).
- Overlapping catalog names are replaced longest first, so `Juan García`
  no longer leaves `[NOMBRE-001]-López` behind (#21).
- If the answer cannot be written to stdout, veil now fails closed
  (`VEIL_INTERNAL`) instead of exiting 0 with no answer, which Claude Code
  read as "proceed with the original input".

### Security

- GO-2026-6218 (quadratic complexity in `net/url`, reachable through the
  policy schema loader): fixed by building with Go 1.26.11.

## [0.1.0] - 2026-09-26

### Added

- `veil claude-code` and `veil opencode`: a guard that reads one host hook
  event on stdin and answers allow, deny or rewrite.
- Detectors for Spanish DNI/NIE (mod-23), IBAN (mod-97), email, Spanish phone
  numbers, a name catalog (`VEIL_CATALOG`), secret file paths and unscannable
  binary or base64 tool output.
- Rewrite with stable per-session pseudonyms (`[DNI-001]`, `[NOMBRE-001]`),
  and rehydration of real values in `write`, `edit`, `multiedit` and `patch`
  tool arguments.
- File-backed pseudonym store under `XDG_STATE_HOME/veil/sessions`.
- OpenCode plugin (`adapters/opencode/veil-plugin.js`) for `chat.message`,
  the message and system transforms, `tool.execute.before` and
  `tool.execute.after`; it fails closed on any unexpected answer.
- Capability matrix per host and event.

[Unreleased]: https://github.com/FullFran/veil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FullFran/veil/releases/tag/v0.1.0
