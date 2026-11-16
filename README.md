<p align="center"><img src="assets/logo.svg" alt="veil logo" width="120" height="120"></p>

# veil

[![ci](https://github.com/FullFran/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/FullFran/veil/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/FullFran/veil/badge)](https://scorecard.dev/viewer/?uri=github.com/FullFran/veil)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16829/badge)](https://www.bestpractices.dev/projects/16829)

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
  with spaces, dots or dashes (`ES91 2100 0418 …`, `FR14 2004 1010 … 606`,
  `12.345.678-Z`, `600 12 34 56`, `699.123.457`, `+34 600 123 456`,
  `(+34) 612 345 670`), only in those strict shapes, with the checksum
  checked, and never as part of a date, an amount or a longer run of digit
  groups. A separated IBAN of any country must also have that country's
  length in the SWIFT IBAN Registry (ISO 13616). A value written two ways
  shares one token, and rehydration gives back its compact form
  (`12345678Z`, `+34612345670`). Email addresses may carry non-ASCII
  letters in the local part and the domain (`josé@bücher.example.de`,
  RFC 6531).
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
  disk, encrypted, in a 0600 file under `XDG_STATE_HOME/veil/sessions` (or
  the OS temp dir); see [The pseudonym store](#the-pseudonym-store). It
  exists because OpenCode's shim spawns a fresh `veil` process per hook
  call, so an in-memory mapping could not survive between calls. Losing
  that directory (e.g. a temp-dir cleanup mid session) means veil mints
  fresh tokens from `-001` again for anything seen again — it will not
  reuse a stale numbering, but it also will not remember that `[DNI-001]`
  used to mean a specific DNI in an already-completed conversation.
- veil ships detectors for Spanish DNI/NIE (mod-23 checksum), IBAN
  (mod-97 checksum), email, Spanish phone numbers, a sensitive-file-path
  detector (`.env`, SSH private keys, and similar), a client name catalog
  (optional, see below), and unscannable binary/base64 tool output. It is
  not a general-purpose PII scanner.

## The pseudonym store

This is **pseudonymisation** in the sense of GDPR art. 4(5) and ISO/IEC
20889, not anonymisation: the text the model sees is still personal data,
and the store is the "additional information" that has to be kept
separately, under technical measures. veil keeps it encrypted at rest.

### Format

Each session is one [age v1](https://c2sp.org/age) file
(`age-encryption.org/v1`, Go library `filippo.io/age`) at
`<state>/veil/sessions/<session>.age`, mode 0600, encrypted to one X25519
recipient. The plaintext inside is a JSON mapping (`"version": 2`). No real
value and no `category:original` key is on disk in clear. Writes go
through a new temp file (created with `O_EXCL`, mode 0600, after removing
any leftover or planted link), `fsync`, a rename and an `fsync` of the
directory, so a write is durable when it returns, even across a power
loss. A sibling `<session>.json.lock` serializes writers across
processes (2 s deadline, then `VEIL_STORE_LOCKED`). The lock is a kernel
lock on that file (`flock(2)` on Linux, macOS and the BSDs, `LockFileEx`
on Windows), so the kernel releases it when its holder dies: a crash never
leaves a session locked forever, and a lock file with no holder (left by a
crash, or by an older veil) is taken over. The holder unlinks the file
before releasing it, and a process that locked a file no longer at the
path retries, so two writers are never let in. **Hosts must not run two veil
versions on the same store concurrently:** an older veil (v0.x,
create-exclusive lock file) and this one (kernel lock) do not exclude each
other, so stop every old veil before the first new one runs. On Windows the empty lock file stays after
use.

The sessions directory must be private: veil creates it 0700, tightens an
existing one that group or others can reach to 0700, and fails closed
with `VEIL_STORE_IO` if it belongs to another user (the OS temp-dir
fallback is shared).

### Key sources

veil takes the store key, an age X25519 identity (`AGE-SECRET-KEY-1…`, the
format `age-keygen` writes; comments allowed), from the first source that
applies:

1. **Host, by descriptor.** `VEIL_KEY_FD=<n>` names an inherited file
   descriptor the host writes the identity to. Only the number travels in
   the environment, never the key (`/proc/<pid>/environ` is readable by the
   same user). The descriptor must be 3 or higher: 0, 1 and 2 are veil's
   stdin (the hook event), stdout and stderr, and are rejected with
   `VEIL_STORE_KEY_INVALID`. A host key always wins. If `VEIL_KEY_FD` is
   set but gives no usable key, veil fails closed; it never falls back to
   another source.
2. **systemd credential.** `$CREDENTIALS_DIRECTORY/veil-store-key`, when
   veil runs under a unit with `LoadCredential=veil-store-key:…` or
   `LoadCredentialEncrypted=` (Linux). If the unit has credentials but not
   this one, veil goes on to the keyring.
3. **OS keyring** (Secret Service on Linux, Keychain on macOS, Credential
   Manager on Windows; service `veil`, account `pseudonym-store-key`). veil
   generates a key there on the first write, so standalone use (the Claude
   Code hook) needs no setup. Reads never generate a key.
4. **None of these** (for example a headless box with no D-Bus session):
   veil fails closed and mints no marker.

Every key failure denies the event with a typed problem
([Failures](#failures)); none falls back to plaintext.

| Failure | Code |
| --- | --- |
| No key for an existing store, or `VEIL_KEY_FD` unusable | `VEIL_STORE_KEY_MISSING` |
| Key is not an age X25519 identity, does not open the file, or `VEIL_KEY_FD` is below 3 | `VEIL_STORE_KEY_INVALID` |
| Session file fails to decrypt, authenticate or parse | `VEIL_STORE_CORRUPT` |
| OS keyring unreachable | `VEIL_STORE_KEYRING_UNAVAILABLE` |
| Lock held past the deadline | `VEIL_STORE_LOCKED` |
| Session retired (removed without readable counters) | `VEIL_SESSION_RETIRED` |

### Commands

Hosts read and delete a session's pseudonyms through veil, not by parsing
or removing its files:

```sh
veil store reveal <session>          # stdout: {"markers":[{"marker":"[DNI-001]","category":"DNI","value":"12345678Z"}]}
veil store forget <session> [...]    # removes each session's store and its lock
veil store find --value <value|->    # stdout: {"sessions":[{"session":"sess-1","categories":["DNI"]}]}
veil store sweep                     # stdout: {"forgotten":["sess-0"],"skipped":[],"failed":[]}
```

- `reveal` prints every marker of the session and the real value it
  stands for, sorted by category and number, for a host's own "what veil
  hid" view. It needs the key, like any read. An unknown session prints
  `{"markers":[]}`.
- `forget` removes each named session's age file, any v1 file, any
  interrupted write (v1 or v2 temp file) and its lock, holding the lock
  while it deletes. It keeps the session's counters file, which holds no
  personal data, so the session id never reuses a marker number (see
  [Retention](#retention-and-data-subject-requests)). It needs no key, on purpose: a lost key must never
  block an erasure, and without the key the file is unreadable anyway. An
  unknown session succeeds.
- `find` lists the sessions whose store holds a value, and the categories
  it was hidden under; it never prints the value or any other value. See
  [Retention and data subject requests](#retention-and-data-subject-requests).
- `sweep` removes the sessions unused for longer than the policy's
  `store.ttl`. See below.
- All exit 0 on success, 1 with a problem line on a store failure, 2 on
  bad arguments. On a failure stdout is empty, except for a `sweep` that
  failed on some sessions: it still prints its answer (session ids only,
  the failed ones under `failed`) before the problem line, and exits 1.

### Retention and data subject requests

GDPR art. 5(1)(e) (storage limitation) asks that personal data be kept no
longer than needed; arts. 15 and 17 give people the right to access and to
erase their data. veil supplies the mechanism; **deciding retention
periods, verifying who is asking, answering within the legal deadline and
erasing the same data from everything else that holds it (host
transcripts, logs, backups) stays the organisation's job.**

**Retention.** Set a TTL in the policy (see [Policy](#policy)):

```json
{ "version": "1.0", "detectors": { "dni": { "action": "rewrite" } }, "store": { "ttl": "P30D" } }
```

`store.ttl` is an ISO 8601 duration as JSON Schema's `duration` format
defines it (RFC 3339 Appendix A), limited to days, hours and minutes
(`P30D`, `PT12H`, `P1DT6H`): years and months have no fixed length. It must
be positive. **Without `store.ttl` veil never deletes a session on its own**,
which is the default, so upgrading never removes anyone's data.

- A session expires when it has been **unused** for longer than the TTL.
  Its last use is its file's modification time: every write sets it, and
  so does every token lookup and every rehydration (`reveal` does not).
  Content veil processes cannot set it; whoever can write the private
  sessions directory can, but can delete the files anyway. Copying the
  store without preserving times restarts the clock. Expiry trusts the
  system clock: **a forward jump of the clock (a wrong NTP step, a
  restored VM, a manual change) expires every session older than the TTL
  at the new time at once**, so keep the clock synchronized and choose a
  TTL with margin.
- With a TTL set, **every veil start sweeps** expired sessions, silently
  and without affecting the decision, removing **at most 16 sessions per
  start** so a hook call never does unbounded work (the rest go on later
  starts). `veil store sweep` runs the same sweep without a bound and
  reports it. Both need no key. A session another veil process holds
  locked is never deleted (it is reported under `skipped`), and its last
  use is checked again under the lock (a session used meanwhile is kept
  and not reported). A session that cannot be locked or removed (for
  example a planted symlink as its lock file) is reported under `failed`
  and the sweep goes on with the others.
- Deletion goes through the same path as `forget`, and is durable: the
  directory is synced after the files are removed, so a crash cannot bring
  a deleted session back. Removing a file is not
  media sanitization (NIST SP 800-88 Rev. 2): on SSDs and journaling
  filesystems the old blocks may survive, but they hold age ciphertext. To
  make *every* session unreadable, destroy the store key.
- **Marker numbers are never reused within a session id.** The host's
  history of a resumed session still holds the markers veil sent; if a new
  value got an old `[DNI-001]`, the model would see two people as one and
  rehydrating that marker in a write would put the wrong value on disk. So
  every session keeps a counters file, `<session>.ctr`, which sweep and
  `forget` leave in place: a resumed session carries on at `[DNI-002]`,
  and an old marker is simply unknown (left as it is, never rehydrated to
  a new value). The file holds only how many values of each category the
  session has seen (for example `{"version":1,"counters":{"DNI":1}}`): no
  value, no marker, no mapping, so it is not personal data and not the
  pseudonymisation key. It is plaintext so keyless removal can keep it,
  and it is never swept, since deleting it would reopen the reuse.
  Sessions written by a veil before counters files existed get one on
  their next write, or at removal when the key (or a v1 file) is at hand.
  **One removed without a key that opens it is retired:** removal still
  happens (erasure is never blocked), its counters file becomes the
  tombstone `{"version":1,"retired":true}` (no personal data either), and
  any later event that would mint a marker for that session id fails
  closed with `VEIL_SESSION_RETIRED`, since any number could repeat one
  the host's history holds. The host must continue under a new session
  id.

**Access and erasure requests.** Find, then forget:

```sh
printf '%s\n' '12.345.678-Z' | veil store find --value -
# {"sessions":[{"session":"sess-1","categories":["DNI"]}]}
veil store forget sess-1
```

- `find` matches a value however it was written, the way detection keys
  it: `12.345.678-Z` and `12345678Z` are the same DNI, and an IBAN or
  phone with spaces, dots or dashes matches its compact form.
- Prefer `--value -`, which reads the value from stdin (one line): a value
  on the command line is visible to other local users in the process list
  and stays in shell history.
- `find` needs the key and **fails closed**: a missing or wrong key, or a
  session it cannot read, ends the search with the store's problem code
  and no partial list, since an incomplete answer to such a request is
  worse than none.
- `find` only reads: it never migrates a v1 plaintext session, rewrites a
  file or generates a key.
- `find` decrypts every session and checks every entry, so its duration
  depends on the store's size, not on whether or where the value is. It
  answers only what its caller, who holds the key, could already learn
  with `reveal`.

### Migration from v1

veil before this format kept `<session>.json` in clear. On the first
access to such a session veil reads it, writes it as `<session>.age`, and
removes the plaintext file only once the encrypted file is durable; token numbers carry on where they were. A v1
file that cannot be parsed fails closed with `VEIL_STORE_CORRUPT` and is
left in place.

### Threat model

- **Protects against** reading the store files: an agent's own file or
  shell tools, backups, sync clients, other applications, a copied
  profile. Without the key, a session file reveals neither the values nor
  which categories map to them.
- **Does not protect against** a process of the same user that obtains the
  key: one that asks the OS keyring for it, or reads the host's or veil's
  memory. Real separation needs the host to keep the run's processes away
  from both the key and the keyring (for HagaHarness, its sandbox), and to
  pass the key by descriptor only to veil.

## Configuring the name catalog

Set `VEIL_CATALOG` to a file listing client and worker names — either a
JSON array of strings, or one name per line:

```json
["María Pérez", "Juan García"]
```

Matching is whole-word, and both case- and accent-insensitive (`MARIA
PEREZ`, `maria perez`, and `María Pérez` all match the same catalog
entry). A catalog name joined to another name part by a hyphen or an
apostrophe is replaced whole: `Juan García-López` and `Ana-María Pérez`
are one token each, keyed by the whole written name, so no part of the
surname stays in clear and they never share a token with `Juan García`
or `María Pérez`. A name is cut from the original text at its exact position,
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
  "catalog": { "path": "names.json" },
  "store": { "ttl": "P30D" }
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
- **Retention.** `store.ttl` deletes sessions unused for longer than an
  ISO 8601 duration; without it nothing is deleted (see
  [Retention and data subject requests](#retention-and-data-subject-requests)).
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
(`.github/workflows/release.yml`). What changed in each release, including
the changes a host must act on, is in [`CHANGELOG.md`](CHANGELOG.md).
Verify before use:

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
| `VEIL_KEY_FD`   | the `veil` binary (`cmd/veil`)     | Number of an inherited descriptor holding the store key (an age identity). Set by a host; wins over every other key source. See [Key sources](#key-sources). |
| `CREDENTIALS_DIRECTORY` | the `veil` binary (`cmd/veil`) | Set by systemd; veil reads its `veil-store-key` credential. |
| `VEIL_TIMEOUT_MS` | `adapters/opencode/veil-plugin.js` | Milliseconds to wait for one `veil` answer before failing closed. Defaults to 30000. |

The plugin reads answers up to 64 MiB and never waits forever. When it
fails closed it throws an `Error` carrying the problem's `code` and `type`
(see [Failures](#failures)): its own `VEIL_OUTPUT_TOO_LARGE`,
`VEIL_TIMEOUT` or `VEIL_UNAVAILABLE`, or the binary's code forwarded
unchanged. On `tool.execute.after`, where throwing blocks nothing, it
replaces the tool output with a notice naming the code instead.

## Decision evidence

Every decision (allow, deny or rewrite) produces one **evidence record**:
what veil decided, under which policy, and which kinds of personal data
it found, never what that data was. A host turns it into its own
decision record (under HCS, HCS-0005-R010 requires one for every
permission decision). Failures (see [Failures](#failures)) are not
decisions and produce no record.

### Channels

| Channel | Host mode | How |
| --- | --- | --- |
| `evidence` member | `veil opencode` | An additive member of the answer on stdout: `{"action": …, "evidence": {…}}`. The OpenCode plugin reads only `action`, `reason` and `args`, so existing shims ignore it. |
| JSONL file | both | Set `VEIL_EVIDENCE_FILE` to a file path: each record is appended as one JSON line (file created `0600`, one `O_APPEND` write per record, flushed before veil answers). |

`veil claude-code` keeps its stdout exactly the hook protocol: it is
unverified whether Claude Code tolerates unknown members, so on that host
evidence is only written to `VEIL_EVIDENCE_FILE`.

The record is written **before** veil answers. If `VEIL_EVIDENCE_FILE` is
set and the record cannot be appended, veil writes nothing on stdout and
fails closed with `VEIL_EVIDENCE_WRITE`: no decision is acted on without
its record (mirrors HCS-0005-R012).

### Format

The record is a [CloudEvents 1.0.2](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md)
event in structured JSON mode whose `data` is an
[OCSF 1.9.0](https://schema.ocsf.io/1.9.0/classes/data_security_finding)
**Data Security Finding** (`class_uid` 2006):

```json
{
  "specversion": "1.0",
  "id": "3b57cbde-9b9f-44a5-bda4-ba8b9dc839f8",
  "source": "tag:fullfran.github.io,2026:veil",
  "type": "io.github.fullfran.veil.decision.v1",
  "time": "2026-11-16T22:50:51.097751852Z",
  "datacontenttype": "application/json",
  "dataschema": "https://schema.ocsf.io/1.9.0/classes/data_security_finding",
  "data": {
    "category_uid": 2, "class_uid": 2006, "activity_id": 1, "type_uid": 200601,
    "severity_id": 2, "time": 1794869451097,
    "metadata": {"version": "1.9.0", "uid": "3b57cbde-…", "profiles": ["security_control"],
                 "product": {"name": "veil", "vendor_name": "FullFran", "version": "(devel)"}},
    "finding_info": {"uid": "3b57cbde-…", "title": "veil privacy decision"},
    "action_id": 4, "action": "Modified", "disposition_id": 99, "disposition": "Pseudonymized",
    "actor": {"app_name": "opencode", "session": {"uid": "ses_123"}},
    "data_security": {
      "detection_system_id": 10, "data_lifecycle_state_id": 2, "category_id": 1,
      "policy": {"uid": "sha256:cc0a…", "name": "veil policy", "version": "1.0", "is_applied": true},
      "discovery_details": [
        {"type": "https://w3id.org/dpv/pd#OfficialID", "count": 2, "rule": {"uid": "dni", "name": "DNI"}}
      ]
    },
    "duration": 0,
    "unmapped": {"veil": {"schema": "1", "event": "ToolArgs", "tool": "bash", "catalog_revision": "clients:r42"}}
  }
}
```

| Member | Meaning |
| --- | --- |
| `action_id` / `disposition_id` | allow: 1 Allowed / 1 Allowed; deny: 2 Denied / 2 Blocked; rewrite: 4 Modified / 99 Other (`disposition` `Pseudonymized`) |
| `severity_id` | 1 Informational (allow), 2 Low (rewrite), 3 Medium (deny): a fixed mapping, veil has no severity model |
| `actor` | `app_name` is the host mode; `session.uid` the host's session id, when it sent one |
| `data_security.policy.uid` | The policy digest (see [Policy](#policy)) |
| `data_security.discovery_details` | One entry per detector that fired: `count` occurrences, `rule.uid` the detector id, `type` its [W3C DPV](https://w3id.org/dpv/pd) personal data concept (`name-catalog` `pd:Name`, `email` `pd:EmailAddress`, `phone` `pd:TelephoneNumber`, `dni` `pd:OfficialID`, `iban` `pd:FinancialAccountNumber`). `secret-path` and `binary-content` have no DPV concept: their `type` is the detector id. Absent when nothing was found. |
| `data_security.category_id` | 1 Personal when any personal data detector fired, 6 Security when only `secret-path`/`binary-content` did, absent otherwise |
| `duration` | Evaluation time in milliseconds |
| `unmapped.veil` | veil's own members: `schema` (version of this block), `event` (`PromptSubmit`, `ToolArgs`, `ToolOutput`, `HistoryText`, `SystemPrompt`), `tool` (tool name, for tool events), `catalog_revision` |

DPV 2.3 is a W3C Community Group report, not a W3C Standard, and has no
DNI/NIE-specific concept: `rule.name` keeps veil's own label next to the
DPV IRI.

### Never included

A record never contains a detected value (in clear, compacted, lowercased
or masked), a pseudonym token, a hash or HMAC of a value, a field name or
path, a deny reason, or any prompt, argument, output, history or system
prompt text (HCS-0005-R011). `TestCorpus_NoEvidenceLeaks` checks this over
every case of the Spanish evaluation corpus, and
`TestRun_Evidence_NeverCarriesInput` over every host mode and event kind.

### Catalog changes

The policy digest covers the policy document and the catalog's *path*,
never its names: a hash of a short list of client names can be reversed
by trying candidate names, so veil never records one. A host that needs
catalog changes in its records sets `VEIL_CATALOG_REVISION` to its own
opaque revision of the catalog (1 to 128 characters from `A-Z a-z 0-9 . _
: -`); veil records it as-is in `unmapped.veil.catalog_revision`. An
invalid value blocks every event with `VEIL_CATALOG_REVISION_INVALID`.

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
| `VEIL_STORE_KEY_MISSING` | `store-key-missing` | No store key for an existing store, or `VEIL_KEY_FD` unusable |
| `VEIL_STORE_KEY_INVALID` | `store-key-invalid` | Store key is not an age X25519 identity, or does not open the file |
| `VEIL_STORE_CORRUPT` | `store-corrupt` | A session file cannot be decrypted, authenticated or parsed |
| `VEIL_STORE_KEYRING_UNAVAILABLE` | `store-keyring-unavailable` | OS keyring unreachable |
| `VEIL_STORE_LOCKED` | `store-locked` | Session lock held past the deadline |
| `VEIL_SESSION_RETIRED` | `session-retired` | The session was removed without its marker counters; minting for it would risk a repeated marker, so the host must use a new session id |
| `VEIL_STORE_IO` | `store-io` | The pseudonym store cannot be read or written |
| `VEIL_EVIDENCE_WRITE` | `evidence-write` | `VEIL_EVIDENCE_FILE` is set and the evidence record cannot be appended |
| `VEIL_CATALOG_REVISION_INVALID` | `catalog-revision-invalid` | `VEIL_CATALOG_REVISION` is not an opaque token (`[A-Za-z0-9._:-]{1,128}`) |
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

The baseline at the time of writing (78 cases, default policy):

| label | tp | fp | fn | precision | recall | f1 |
| --- | --: | --: | --: | --: | --: | --: |
| DNI | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| IBAN | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| EMAIL | 10 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| TEL | 15 | 3 | 0 | 0.8333 | 1.0000 | 0.9091 |
| NOMBRE | 13 | 1 | 2 | 0.9286 | 0.8667 | 0.8966 |
| micro | 70 | 4 | 2 | 0.9459 | 0.9722 | 0.9589 |

Known misses, kept on purpose so the numbers stay honest. They need
context or named-entity recognition (#3), not a pattern:

- Names outside the catalog (`nombre-006`, `nombre-007`): missed.
- A catalog name inside a street name (`nombre-010`, `Calle María Pérez
  de la Rosa`): replaced although it is a street. Particles such as `de
  la` are not joined to a name for the same reason: `Juan García de la
  oficina` would be swallowed too.
- Nine bare digits starting with 6-9 that are not a phone, such as an
  invoice number (`tel-012`) or a CLI count (`args-005`): replaced.
- A dot-grouped nine-digit count with no currency (`tel-017`, `712.345.678
  habitantes`): replaced. This is the price of finding `699.123.457`
  (`tel-005`): on the corpus the dot form adds one true positive and one
  false positive, while amounts with decimals or a currency
  (`612.345.678,00 €`, `tel-011`) stay untouched.

The false positives fail in the safe direction (over-redaction).

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
`go test -race` (which includes `TestDomainImportsNoHostAdapter`, failing if
`internal/domain` depends on any `internal/hosts/...` package), the plugin
test, and an architecture gate: an [archsieve](https://github.com/FullFran/archsieve)
snapshot of the base and of the head, compared with
`archsieve diff --fail-on error`. The diff is in the job summary and the
snapshots are uploaded as an artifact. Static analysis runs on every pull
request too: golangci-lint with gosec (`.golangci.yml`; run it locally with
`golangci-lint run ./...`), `govulncheck ./...`, and CodeQL for Go and the
workflows (`.github/workflows/codeql.yml`). The
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

No test touches the real OS keyring: the store's keyring is an interface
and every test injects a fake. The one test against the real keyring is
opt-in and skips when none is reachable:

```bash
VEIL_TEST_REAL_KEYRING=1 go test -run OSKeyring ./internal/pseudonymstore/
```

`test/e2e/opencode` is a separate, scripted acceptance test that drives a
real, installed OpenCode CLI against a local mock model provider, since
that is the only way to prove OpenCode's actual plugin loader and hook
signatures still behave the way this repo's design assumes.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
