<p align="center"><img src="assets/logo.svg" alt="veil logo" width="120" height="120"></p>

# veil

[![ci](https://github.com/FullFran/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/FullFran/veil/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/FullFran/veil/badge)](https://scorecard.dev/viewer/?uri=github.com/FullFran/veil)

A host-agnostic privacy guard for AI coding agents. It inspects what an
agent is about to do and blocks or redacts personal data before it leaves
the machine.

veil is not a compliance product. It enforces exactly what is listed
below, on exactly the hosts listed below, and says so explicitly wherever
it cannot.

## What this is

veil sits between an AI coding agent host (currently Claude Code and
OpenCode) and the outside world. Each host invokes veil with a JSON
description of something it is about to do: a typed prompt, a tool call's
arguments, a tool's output, prior conversation history being resent to
the model, or the system prompt. veil runs that event through a set of
detectors and returns Allow, Deny, or Rewrite.

The domain logic in `internal/domain` has zero knowledge of which host
produced an event. Only the two adapter packages,
`internal/hosts/claudecode` and `internal/hosts/opencode`, know how to
speak each host's wire format.

### Rewrite: stable per-session pseudonyms, not blanket denial

Earlier versions of veil denied any tool call or prompt containing a
detected DNI. That is too blunt for a real agent workflow: an assistant
that is denied outright every time a client's DNI comes up cannot do
anything useful with client data at all. veil now distinguishes two kinds
of finding:

- **Rewritable** (DNI/NIE, IBAN, email, Spanish phone number, a name from
  a client's name catalog): the event proceeds, but every match is
  replaced with a stable pseudonym token — `[DNI-001]`, `[IBAN-001]`,
  `[EMAIL-001]`, `[TEL-001]`, `[NOMBRE-001]` — before it leaves the
  machine. The same original value always gets the same token within one
  session, and a different session never reuses another session's
  numbering. IBAN, DNI/NIE and phone numbers are also found when written
  with spaces, dots or dashes (`ES91 2100 0418 …`, `12.345.678-Z`,
  `600 12 34 56`, `+34 600 123 456`), only in those strict shapes, with
  the checksum checked, and never as part of a date, an amount or a longer
  run of digit groups. A value written two ways shares one token, and
  rehydration gives back its compact form (`12345678Z`).
- **Hard-deny** (a tool call targeting a known secrets-bearing file, or
  tool output veil cannot scan at all — see "Attachments and binary
  content" below): there is no safe rewrite, so the event is blocked
  outright, exactly as before.

Where a host can also write real data to disk (a `write`/`edit`/`patch`
tool call), veil rehydrates: any pseudonym token still present in that
call's arguments is turned back into the real value first, so the file on
disk holds real data, never a placeholder the model was shown instead of
it.

Tool-call arguments are scanned leaf by leaf, nested ones included (a
`multiedit` call's `edits`), and a rewrite answers with the arguments'
own shape: arrays stay arrays, and numbers and booleans keep their type
unless veil rewrote them.

## The capability matrix

The two hosts have genuinely different hook/plugin capabilities. This is
not a limitation of veil's implementation; it is a limitation of what
each host exposes. The matrix below is enforced in code
(`internal/domain/capability.go`), not just documented here: asking veil
to enforce a guarantee a host cannot provide returns an explicit
`UnsupportedCapabilityError`, never a silent allow.

| Capability                                       | Claude Code | OpenCode |
| ------------------------------------------------- | :---------: | :------: |
| Block or rewrite the typed prompt                 |     Yes     |   Yes    |
| Block or rewrite a tool call's arguments          |     Yes     |   Yes    |
| Redact or block a tool call's output               |     No      |   Yes    |
| Rewrite conversation history resent to the model   |     No      |   Yes    |
| Rewrite the system prompt                          |     No      |   Yes    |

This table changed from an earlier version of this README, which claimed
OpenCode had no prompt-level hook at all and treated
`tool.execute.after`'s ability to redact a tool's output as unverified.
Neither claim had actually been checked against a real OpenCode install.
A spike against the real, installed **OpenCode 1.18.32** — a local mock
OpenAI-compatible HTTP server plus a throwing-and-mutating plugin, full
notes in the `downstream harness` repo's `integration notes`, T1 —
corrected both:

- **Claude Code** hooks run as external processes. `UserPromptSubmit`
  fires on the typed prompt before the model sees it and can block (exit
  code 2) or rewrite it. `PreToolUse` fires before a tool call and can
  block or rewrite its arguments. `PostToolUse` is observe-only: it
  cannot block or redact a tool's output, only attach additional context.
  Claude Code has no hook that resends prior-turn history or the system
  prompt through anything rewritable.
- **OpenCode** plugins are in-process JS/TS modules, and every one of the
  hooks below was verified directly against the mock provider (did the
  mock receive the original value, or the mutated one? did it receive
  anything at all?), not assumed from the type definitions alone:
  - `chat.message` fires on the user's typed prompt. **Throwing here
    aborts the whole request before the model is ever contacted**
    (verified: the mock received nothing). **Mutating a part's `text`
    rewrites what the model sees** (verified: the mock received the
    mutated text, and so did OpenCode's own local session storage).
  - `tool.execute.before` blocks (throw) or rewrites (mutate
    `output.args`) a tool call's arguments, as before.
  - `tool.execute.after` fires after a tool already executed. **Throwing
    here does NOT block anything**: the thrown error text just becomes
    the tool's own result, and the conversation continues with the real
    tool call having already run (verified: a throw here still let a
    follow-up request through). **Mutating `output.output` (and
    `output.metadata.output`, when present) redacts the tool's output**
    for both the model and OpenCode's own local session storage
    (verified against the real part shape OpenCode records:
    `{type:"tool", state:{output, metadata:{output}}}` — OpenCode keeps a
    second copy of a tool's output in `metadata.output`, so a fix that
    only mutates `output.output` still leaks the original to local disk).
  - `experimental.chat.messages.transform` fires on every message about
    to be resent to the model, on every turn. **Throwing here aborts the
    request too** (verified). Mutating a text part's `text`, a tool
    part's `state.output`, or a tool part's own `state.input` argument
    values (e.g. a write call's `content`) rewrites what is resent.
  - `experimental.chat.system.transform` fires on the system prompt.
    **Throwing here aborts the request too** (verified). Mutating an
    entry of `output.system` rewrites it.

Net effect: OpenCode is not the weaker host anymore. The real remaining
asymmetry is that Claude Code cannot redact a tool's output at all, while
OpenCode can (by mutation); and a UX one, not a capability one — a
`throw` on OpenCode surfaces as a generic `UnknownError` to the person
using it, not a clean reason the way Claude Code's exit-code-2 does.

## What this cannot do

- **Claude Code: no output redaction.** `PostToolUse` cannot block or
  redact what a tool already returned. If a tool call itself was allowed,
  its output is not filtered by veil on this host.
- **Claude Code: no history or system-prompt rewrite.** There is no hook
  for either, so pseudonym tokens already sent in an earlier turn are the
  only protection for anything Claude Code resends from history.
- **Chat display still shows tokens.** No hook on either host rewrites
  the model's own streamed reply as it is displayed to the person using
  the agent. If the model itself echoes a pseudonym token back in its
  answer, that token — not the real value — is what appears on screen.
  This is intentional: the model never saw the real value to begin with.
- **Attachments and binary content: fail closed, not scanned.** A regex
  detector cannot inspect raw binary bytes or a base64-encoded blob (e.g.
  an MCP tool returning file bytes as text). veil's `binary-content`
  detector flags exactly this shape (invalid UTF-8, or a long run of
  base64-alphabet characters) on a tool's output and denies it outright:
  there is no safe rewrite for content that cannot be inspected.
- The pseudonym mapping (`internal/pseudonymstore`) is per-session, on
  disk, in a 0600 file under `XDG_STATE_HOME/veil/sessions` (or the OS
  temp dir). It exists because OpenCode's shim spawns a fresh `veil`
  process per hook call, so an in-memory mapping could not survive
  between calls. Losing that directory (e.g. a temp-dir cleanup mid
  session) means veil mints fresh tokens from `-001` again for anything
  seen again — it will not reuse a stale numbering, but it also will not
  remember that `[DNI-001]` used to mean a specific DNI in an
  already-completed conversation.
- veil ships detectors for Spanish DNI/NIE (mod-23 checksum), IBAN
  (mod-97 checksum), email, Spanish phone numbers, a sensitive-file-path
  detector (`.env`, SSH private keys, and similar), a client name catalog
  (optional, see below), and unscannable binary/base64 tool output. It is
  not a general-purpose PII scanner.

## Configuring the name catalog

Set `VEIL_CATALOG` to a file listing client and worker names — either a
JSON array of strings, or one name per line:

```json
["María Pérez", "Juan García"]
```

Matching is whole-word, and both case- and accent-insensitive (`MARIA
PEREZ`, `maria perez`, and `María Pérez` all match the same catalog
entry). A name is cut from the original text at its exact position,
whatever other characters (`¿`, `€`, `«`, emoji) the text holds. If
`VEIL_CATALOG` is set but cannot be read or parsed, veil fails
closed at startup: every event is blocked with a
`VEIL_CATALOG_UNREADABLE` problem (see [Failures](#failures)) rather than
silently running without the catalog. If `VEIL_CATALOG` is unset (and the
policy names no `catalog.path`, see below), the name-catalog detector is
simply not registered.

## Policy

Which detectors run, and what veil does with each one's findings, is a
policy file: data, not code. With no policy configured, veil uses the
**default policy** embedded in the binary,
[`internal/policy/default.json`](internal/policy/default.json), which is
exactly the behaviour described above. A test
(`TestRun_DefaultPolicy_Equivalence`) proves every sample event gives
byte-identical output with no policy, with `VEIL_POLICY` pointing at the
default file, and as recorded before policies existed.

Set `VEIL_POLICY` to a policy file to use your own:

```json
{
  "version": "1.0",
  "detectors": {
    "dni": { "action": "deny" },
    "iban": { "action": "rewrite" },
    "email": { "action": "rewrite" },
    "secret-path": { "action": "deny" },
    "binary-content": { "action": "deny" },
    "name-catalog": { "action": "rewrite" }
  },
  "catalog": { "path": "names.json" }
}
```

- **Schema.** Every policy is validated against
  [`internal/policy/policy.schema.json`](internal/policy/policy.schema.json),
  a JSON Schema 2020-12 document. Unknown members, unknown detectors and
  unknown actions are rejected. `version` names the contract (`1.0`).
- **Detectors.** A detector missing from `detectors` does not run.
  `rewrite` replaces each match with a pseudonym token; `deny` blocks the
  event. `secret-path` and `binary-content` accept only `deny`: there is no
  safe rewrite for them. Detector ids map to pseudonym categories one to
  one: `dni` (DNI/NIE) -> `DNI`, `iban` -> `IBAN`, `email` -> `EMAIL`,
  `phone` -> `TEL`, `name-catalog` -> `NOMBRE`. veil always runs detectors
  in its own fixed order, whatever order the file lists them in.
- **Catalog.** `catalog.path` is resolved relative to the policy file.
  `name-catalog` runs only when a catalog is set, by `catalog.path` or by
  `VEIL_CATALOG`. Setting both, or setting either while the policy does not
  enable `name-catalog`, is rejected as ambiguous rather than ignoring one.
- **Fails closed.** If `VEIL_POLICY` is set, veil never falls back to the
  default policy: an unreadable file blocks every event with
  `VEIL_POLICY_UNREADABLE`, and a file that is not exactly one JSON
  document (duplicate members included), breaks the schema or is ambiguous
  blocks every event with `VEIL_POLICY_INVALID` (see [Failures](#failures)).
- **Digest.** A policy is identified by `sha256:<hex>`, the SHA-256 of its
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS) canonical form:
  whitespace and member order do not change it, and any change of content
  does. It covers the policy document only (the catalog's *path*, never the
  names in it), so it is safe to put in a decision record.
- **Not a policy language.** There is no Rego, OPA or CEL in veil.
  Conditions such as tenant, purpose or provider are authority, which under
  HCS belongs to the host (HCS-0005); a host that needs them runs its own
  policy engine and picks which veil policy file to use.

Check a policy, and print its digest, before deploying it:

```bash
veil policy my-policy.json   # or: VEIL_POLICY=my-policy.json veil policy
# {"source":"my-policy.json","version":"1.0","digest":"sha256:…"}
veil policy                  # the embedded default policy
```

On failure it writes one problem line on stderr and exits 1 (2 for bad
arguments).

## Installing on Claude Code

Build the binary and point a hook entry at it in your Claude Code
`settings.json`:

```bash
go build -o /usr/local/bin/veil ./cmd/veil
```

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "veil claude-code" }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "veil claude-code" }
        ]
      }
    ]
  }
}
```

Claude Code invokes `veil claude-code` for each matching event, feeding
the hook's JSON payload on stdin. Set `VEIL_CATALOG` in the environment
Claude Code's hooks run in if you want the name catalog detector active.

## Prebuilt binaries

Every release publishes, as assets, `veil-<os>-<arch>` binaries built with
`CGO_ENABLED=0` (`linux`, `darwin` and `windows`, each on `amd64` and
`arm64`; Windows files end in `.exe`), the OpenCode plugin `veil-plugin.js`,
and a `SHA256SUMS` file covering all of them
(`.github/workflows/release.yml`). Verify before use:

```bash
curl -fsSLO https://github.com/FullFran/veil/releases/download/v0.1.0/veil-linux-amd64
curl -fsSLO https://github.com/FullFran/veil/releases/download/v0.1.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

The workflow runs on every `v*` tag push. To publish assets for a tag that
already exists, run it by hand (`gh workflow run release.yml -f tag=v0.1.0`);
it builds that tag's sources and does not move the tag.

### Verifying a release

Releases built by the current workflow also publish two supply-chain files.
They are not listed in `SHA256SUMS`, so the digests of the other assets stay
the same:

- `veil.intoto.jsonl`: [SLSA](https://slsa.dev/spec/v1.0/provenance)
  build provenance v1 for every asset in `SHA256SUMS`, as an in-toto
  statement in a [Sigstore](https://www.sigstore.dev/) bundle signed with the
  release workflow's GitHub identity. The same attestation is stored in the
  repository's [attestations](https://github.com/FullFran/veil/attestations).
  It is generated in the same job as the build, which is SLSA Build Level 2.
- `SHA256SUMS.sigstore.json`: a keyless Sigstore (cosign) signature of
  `SHA256SUMS`.

Releases published before this workflow change (such as v0.1.0) have
neither file.

A host checks provenance before it pins an asset's sha256. With the
[GitHub CLI](https://cli.github.com/) (a release with `gh attestation`):

```bash
TAG=v0.3.0   # the release you are pinning
gh release download "$TAG" --repo FullFran/veil \
  --pattern veil-linux-amd64 --pattern veil.intoto.jsonl
gh attestation verify veil-linux-amd64 \
  --repo FullFran/veil \
  --bundle veil.intoto.jsonl \
  --signer-workflow FullFran/veil/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" \
  --deny-self-hosted-runners
sha256sum veil-linux-amd64   # the digest to pin
```

Leave out `--bundle veil.intoto.jsonl` to fetch the attestation from GitHub
instead of the release. `--source-ref` holds for releases built by a tag
push; a release rebuilt by hand runs from `main`, so use
`--source-ref refs/heads/main` for it.

To check every asset with [cosign](https://docs.sigstore.dev/cosign/) (v3, the
version that signs it) and the checksum file alone:

```bash
gh release download "$TAG" --repo FullFran/veil
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/FullFran/veil/\.github/workflows/release\.yml@refs/(tags/v[0-9].*|heads/main)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check SHA256SUMS
```

The release workflow runs both checks on the files before it publishes them.

## Installing on OpenCode

Build the binary (or download a prebuilt one, above), then wire the shim
plugin in `adapters/opencode`:

```bash
go build -o /usr/local/bin/veil ./cmd/veil
```

Register `adapters/opencode/veil-plugin.js` as an OpenCode plugin per your
OpenCode configuration (an absolute path in the config's `plugin` array
works; see `test/e2e/opencode/run.mjs` for a full example config). The
shim spawns the `veil` binary (or the path in `VEIL_BINARY`) with the
`opencode` argument for every event, and either throws to block or
mutates the relevant output field to rewrite, based on veil's response.
It wires all five hooks veil supports on this host: `chat.message`,
`tool.execute.before`, `tool.execute.after`,
`experimental.chat.messages.transform`, and
`experimental.chat.system.transform`.

Environment variables the plugin and binary read:

| Variable        | Read by                          | Meaning                                                                 |
| --------------- | --------------------------------- | ------------------------------------------------------------------------ |
| `VEIL_BINARY`   | `adapters/opencode/veil-plugin.js` | Path to the `veil` binary. Defaults to `veil` (resolved via `PATH`).      |
| `VEIL_CATALOG`  | the `veil` binary (`cmd/veil`)     | Path to a name catalog file (JSON array or one-name-per-line). Optional.  |
| `VEIL_POLICY`   | the `veil` binary (`cmd/veil`)     | Path to a policy file (see [Policy](#policy)). Optional; unset means the embedded default policy. |
| `XDG_STATE_HOME`| the `veil` binary (`cmd/veil`)     | Base directory for the per-session pseudonym store. Falls back to the OS temp dir. |
| `VEIL_TIMEOUT_MS` | `adapters/opencode/veil-plugin.js` | Milliseconds to wait for one `veil` answer before failing closed. Defaults to 30000. |

The plugin reads answers up to 64 MiB and never waits forever. When it
fails closed it throws an `Error` carrying the problem's `code` and `type`
(see [Failures](#failures)): its own `VEIL_OUTPUT_TOO_LARGE`,
`VEIL_TIMEOUT` or `VEIL_UNAVAILABLE`, or the binary's code forwarded
unchanged. On `tool.execute.after`, where throwing blocks nothing, it
replaces the tool output with a notice naming the code instead.

## Failures

When veil cannot make a decision it fails closed and reports why as one
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem details object,
written as a single JSON line on stderr (nothing on stdout):

```json
{"type":"tag:fullfran.github.io,2026:veil/problems/store-corrupt","title":"Pseudonym store is corrupt","detail":"…","code":"VEIL_STORE_CORRUPT"}
```

This is a **non-HTTP profile** of RFC 9457 (Appendix C allows other
carriers), not a claim of HTTP conformance:

- `type` is the stable identifier: branch on it, or on `code`, which mirrors
  it as a token. Never parse `title` or `detail`; they are human text.
- `status` is omitted: it is an HTTP status code and veil is not HTTP.
  `instance` is omitted: events carry no identifier.
- `title` and `detail` are fixed text per type. They never contain input,
  a detected value, a path or a session id.
- Types are [RFC 4151](https://www.rfc-editor.org/rfc/rfc4151) `tag:` URIs
  under `tag:fullfran.github.io,2026:veil/problems/`: globally unique
  without a domain the project would have to own. They are identifiers,
  not links. A type never changes once released.

### Exit codes

The exit code carries only the class; the detail is in the problem.

| Exit | Class |
| --- | --- |
| 0 | A decision was made: allow, deny or rewrite (the decision is on stdout) |
| 2 | Usage: bad arguments |
| 1 | Failed closed: the event must not proceed |

Claude Code is the one exception: it treats every nonzero exit other than
2 as a non-blocking error and lets the prompt or tool call through, so on
`veil claude-code` a failure exits **2**, the only code that blocks. Its
`UserPromptSubmit` deny also exits 2 (Claude Code's contract); the problem
line on stderr is what tells a failure apart.

### Types

| Code | Type suffix | When |
| --- | --- | --- |
| `VEIL_USAGE` | `usage` | Bad arguments |
| `VEIL_INPUT_INVALID` | `input-invalid` | stdin is not one valid event for the host |
| `VEIL_CATALOG_UNREADABLE` | `catalog-unreadable` | The name catalog (`VEIL_CATALOG` or the policy's `catalog.path`) is unreadable or unparsable |
| `VEIL_POLICY_UNREADABLE` | `policy-unreadable` | `VEIL_POLICY` set but the file cannot be read |
| `VEIL_POLICY_INVALID` | `policy-invalid` | The policy is not one JSON document, breaks the schema, or is ambiguous |
| `VEIL_CAPABILITY_UNSUPPORTED` | `capability-unsupported` | The host cannot enforce the decision (e.g. Claude Code tool-output redaction) |
| `VEIL_STORE_KEY_MISSING` | `store-key-missing` | Pseudonym store key not configured (reserved for #5) |
| `VEIL_STORE_KEY_INVALID` | `store-key-invalid` | Pseudonym store key malformed or wrong (reserved for #5) |
| `VEIL_STORE_CORRUPT` | `store-corrupt` | A pseudonym session file cannot be parsed |
| `VEIL_STORE_KEYRING_UNAVAILABLE` | `store-keyring-unavailable` | OS keyring unreachable (reserved for #5) |
| `VEIL_STORE_LOCKED` | `store-locked` | Session lock held past the deadline (reserved for #5; today reported as `VEIL_INTERNAL`) |
| `VEIL_STORE_IO` | `store-io` | The pseudonym store cannot be read or written |
| `VEIL_EVIDENCE_WRITE` | `evidence-write` | Evidence sink unwritable (reserved for #6) |
| `VEIL_TIMEOUT` | `timeout` | OpenCode plugin: the binary did not answer in time |
| `VEIL_OUTPUT_TOO_LARGE` | `output-too-large` | OpenCode plugin: the answer exceeded its buffer |
| `VEIL_UNAVAILABLE` | `unavailable` | OpenCode plugin: the binary cannot run, or failed without a problem line, or its answer is malformed |
| `VEIL_INTERNAL` | `internal` | Anything no other type describes (still fails closed) |

The codes and types are defined once, in `internal/problem`.

### Mapping to HCS-0006 (HagaHarness and other HCS hosts)

veil does not emit HCS-0006 codes: that set is closed and owned by the
host (HCS-0006-R002), and a condition no HCS document defines is reported
as a problem type the distribution owns, never as an HCS error
(HCS-0006, section 3). A host that runs veil as a guard maps its problems
itself. Suggested mapping:

| veil | HCS-0006 `code` |
| --- | --- |
| `VEIL_TIMEOUT` | `timeout` |
| everything else | `permission_denied` |

Whatever the mapping, a guard that fails means the request must not reach
the model provider (HCS-0008-R020) and the operation is denied
(HCS-0005-R014).

## Evaluation corpus

No public corpus covers Spanish DNI, NIE or IBAN, so veil ships a synthetic
one: [`testdata/corpus/es/v1`](testdata/corpus/es/v1). Every value in it is
made up (checksums computed, not copied from real people). The
ai4privacy `pii-masking-200k` dataset was considered and not used: it has
no Spanish split and declares no licence in its dataset card.

- `corpus.jsonl` has one record per line: either `{"id", "tags", "text"}`
  (a prompt) or `{"id", "tags", "tool", "args"}` (a tool call, nested
  arguments included). Gold annotations are inline, `[[LABEL:value]]`, with
  labels `DNI`, `IBAN`, `EMAIL`, `TEL` and `NOMBRE`; the loader strips them
  and derives the offsets, so nobody types offsets by hand. A span covers
  the whole value as written, separators and `+34` included. Every personal
  name is annotated `NOMBRE`, including names outside the catalog.
- It covers valid and invalid control letters and check digits, separated
  forms, near misses (dates, amounts, invoice numbers, digit runs), names
  next to Unicode, names outside the catalog, and nested tool arguments.
- `catalog.json` is the name catalog the corpus is evaluated with.
- `baseline.json` holds the committed numbers.

Run it:

```bash
go run ./cmd/veil-eval            # table: per label and micro, plus latency
go run ./cmd/veil-eval -check     # also exit 1 if worse than baseline.json
go run ./cmd/veil-eval -json      # the same report as JSON
go run ./cmd/veil-eval -policy my-policy.json
```

How to read it:

- A predicted span is every place veil would replace with a token: each
  occurrence of a rewritable finding's match, in the prompt or in each
  tool-argument field. Detection uses the policy's detectors whatever their
  action, so `deny` does not change what is measured.
- **Strict span match, MEDDOCAN convention**: a prediction is a true
  positive only if field, start offset, end offset (code points) and label
  all equal a gold span. Off by one character counts as one false positive
  and one false negative.
- **precision** = tp / (tp + fp): how often a replacement was right.
  **recall** = tp / (tp + fn): how much personal data was caught. For a
  privacy guard, recall is the number that matters most. **micro** sums
  tp, fp and fn over every label before dividing, so frequent labels
  weigh more.
- **latency** is `Evaluate` time per event (detection plus rewrite, with an
  in-memory pseudonym store), over every repeat of every event: p50, p95
  and max in microseconds. Process start-up and disk I/O are not included.

The baseline at the time of writing (73 cases, default policy):

| label | tp | fp | fn | precision | recall | f1 |
| --- | --: | --: | --: | --: | --: | --: |
| DNI | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| IBAN | 10 | 0 | 1 | 1.0000 | 0.9091 | 0.9524 |
| EMAIL | 8 | 0 | 1 | 1.0000 | 0.8889 | 0.9412 |
| TEL | 12 | 3 | 2 | 0.8000 | 0.8571 | 0.8276 |
| NOMBRE | 9 | 2 | 3 | 0.8182 | 0.7500 | 0.7826 |
| micro | 59 | 5 | 7 | 0.9219 | 0.8939 | 0.9077 |

Known misses, kept on purpose so the numbers stay honest: a separated
foreign IBAN, an email with a non-ASCII local part, a dot-separated phone,
`(+34)` in parentheses, names outside the catalog, and a catalog name
inside a longer compound surname or a street name.

**Gate.** `TestCorpus_MeetsBaseline` (in `go test ./...`, so CI runs it)
fails when recall on any label drops below `baseline.json`, or when p95
latency exceeds its absolute budget (`latencyP95BudgetMicros`, 2000 µs;
absolute because shared CI runners are too noisy for a relative bound).
After a deliberate improvement, pin the new numbers with
`go run ./cmd/veil-eval -write-baseline` and commit `baseline.json`. A
change that lowers recall needs the same command and a reason in the pull
request.

## Development

Every pull request runs `.github/workflows/ci.yml`: `gofmt -l`, `go vet`,
`go test` (which includes `TestDomainImportsNoHostAdapter`, failing if
`internal/domain` depends on any `internal/hosts/...` package), the plugin
test, and an architecture gate: an [archsieve](https://github.com/FullFran/archsieve)
snapshot of the base and of the head, compared with
`archsieve diff --fail-on error`. The diff is in the job summary and the
snapshots are uploaded as an artifact. The
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/FullFran/veil)
runs weekly and on every push to `main`. To report a vulnerability, see
[`.github/SECURITY.md`](.github/SECURITY.md).

To run the architecture gate locally (archsieve is not on npm; Node.js 22+):

```bash
git clone --depth 1 --branch v0.6.0 https://github.com/FullFran/archsieve /tmp/archsieve
(cd /tmp/archsieve && npm ci --omit=dev --ignore-scripts)
node /tmp/archsieve/bin/archsieve.mjs scan . --ref origin/main -o /tmp/base.json
node /tmp/archsieve/bin/archsieve.mjs scan . --ref HEAD -o /tmp/head.json
node /tmp/archsieve/bin/archsieve.mjs diff /tmp/base.json /tmp/head.json --format md --fail-on error
```

```bash
go test ./...
go vet ./...
gofmt -l .
go run ./cmd/veil-eval -check   # detector quality against the corpus baseline
node --test adapters/opencode/veil-plugin.test.mjs   # the plugin against stub binaries
node test/e2e/opencode/run.mjs   # end-to-end acceptance test; see test/e2e/opencode/README.md
```

This project is built test-first: every detector, every host adapter, and
the capability matrix itself has a test that was written and observed to
fail before the corresponding implementation was written. See
`internal/domain/leak_test.go` for the headline suite proving the guard
can actually go red, including the capability-error test for Claude
Code's tool-output-redaction gap, which is the most important test in the
repository.

`test/e2e/opencode` is a separate, scripted acceptance test that drives a
real, installed OpenCode CLI against a local mock model provider, since
that is the only way to prove OpenCode's actual plugin loader and hook
signatures still behave the way this repo's design assumes.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
