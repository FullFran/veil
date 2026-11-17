# Assurance case

Why veil's security requirements are met. Each claim says what is argued,
and points to evidence anyone can re-run. The threats themselves, with their
mitigations and tests, are in [threat-model.md](threat-model.md).

## Top claim

**veil does not let personal data it is configured to detect leave the
machine through an event it guards, and it does not create a new way to
leak or tamper with that data.**

## Threat model and trust boundaries

The assets are the user's personal data and the pseudonym mapping. The
untrusted inputs are everything a host sends (prompts, tool arguments and
tool output, written by the user, the agent or any file or web page the
agent read), the policy and catalog files, and the files in the store
directory. The trust boundaries are drawn in the data-flow diagram of
[threat-model.md](threat-model.md#data-flow-diagram); the threats per
element are enumerated with LINDDUN (privacy) and STRIDE (security) in the
same document, each with its status and the test that proves it.

## Sub-claims

| Claim | Argument | Evidence |
|---|---|---|
| C1. Every guarded event is inspected | Each host adapter maps every hook it registers to an event the policy evaluates; unsupported events fail closed | The capability matrix in the README; adapter tests; `FuzzPipeline` |
| C2. A detected value is never sent back in clear | Rewrites replace every finding before encoding; deny reasons carry categories, not values; failures carry codes, not input | `internal/domain/leak_test.go`; `FuzzPolicy_Evaluate`; `FuzzPipeline` (both hosts); `cmd/veil/output_test.go` |
| C3. Errors never fail open | Every error path returns a problem and the host's blocking exit code; stdout write failures are errors too | `internal/problem` tests; `cmd/veil/main_test.go`; the ACS fuzz targets |
| C4. The store does not leak or mix data | One age-encrypted file per session with owner-only modes; injective file names; fail closed without a key or a session id | `internal/pseudonymstore` tests; `FuzzEncodeStem_Injective`; `FuzzDecrypt`; `FuzzParseIdentity` |
| C5. Untrusted input is validated | Strict JSON decoding, a JSON Schema for the policy, bounded sizes, path checks on session ids | `FuzzParse`; `FuzzServe`; policy and store tests |
| C6. Releases are what the source says | Pinned actions, read-only default tokens, reproducible builds, SLSA provenance and a Sigstore signature verified before publishing | `test/supplychain`; [docs/releasing.md](releasing.md); [README, Verifying a release](../README.md#verifying-a-release) |

## Secure design principles applied

Fail-safe defaults (fail closed, everything off unless the policy enables
it); complete mediation (every registered hook goes through the policy);
least privilege (owner-only store files, read-only CI tokens, no network);
economy of mechanism (one decision function, one failure registry, one
publishing path); separation of privilege at release (build and signing by
the workflow identity, not a person's key); input validation at every trust
boundary.

## Common weaknesses countered

| Weakness (CWE) | Countermeasure |
|---|---|
| CWE-22 path traversal | Session ids become base32 file names inside `ids/`; tested and fuzzed |
| CWE-20 improper input validation | Schema-validated policy, strict JSON decoding, fuzzed parsers |
| CWE-532 / CWE-209 sensitive data in logs or errors | Problem details carry a stable code, never input, paths or ids |
| CWE-362 race condition | Kernel file locks per session; tests run under `-race` in CI |
| CWE-327 broken crypto | Only age v1 (X25519, ChaCha20-Poly1305) and SHA-256, from maintained libraries |
| CWE-1357 / supply chain | Dependabot, govulncheck, osv-scanner, pinned actions, signed and attested releases |

## Residual risk

Accepted risks (for example, data veil is not configured to detect, or a
host that does not call veil) are listed with their owner in
[threat-model.md](threat-model.md#accepted-residual-risks).
