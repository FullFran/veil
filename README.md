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
produced an event. Only the adapter packages,
`internal/hosts/claudecode`, `internal/hosts/opencode` and
`internal/hosts/acs` (the OWASP Agent Control Standard, one package per
ACS version), know how to speak each host's wire format.

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
  shares one token, keyed by its canonical form (`12345678Z`,
  `ES9121000418450200051332`). A Spanish phone is keyed by its ITU-T
  E.164 form whether it is written bare or with `+34`, `0034`, `(+34)` or
  `(0034)`: `612345678`, `612 345 678`, `0034612345678` and
  `(+34) 612-345-678` are one `[TEL-001]`. **Rehydration writes back the
  first written form** the session saw for that marker, not the key: if
  the model first read `612 345 678` from a file, `[TEL-001]` comes back
  as `612 345 678` in a later write or edit, so an edit whose old text
  carries the marker matches the file's bytes. Later forms of the same
  number share the marker and never change what it rehydrates to. A
  session that already holds separate markers for the bare and the
  prefixed form (minted before this keying) keeps them, since a marker
  never changes meaning within a session: each still rehydrates to what it
  was minted for, and a new mention of the number gets a marker keyed by
  its E.164 form. Email addresses may carry non-ASCII
  letters in the local part and the domain (`josé@bücher.example.de`,
  RFC 6531). Unicode lookalikes are found too: compatibility forms such as
  full-width digits and letters (`１２３４５６７８Ｚ`, `zed＠example.org`),
  no-break spaces, format characters inside a value (a zero-width space in
  `1234<U+200B>5678Z`, a soft hyphen, a word joiner) and decimal digits of
  other scripts. veil scans an NFKC view of the text (Unicode UAX #15)
  with Default_Ignorable_Code_Point characters (UAX #44) removed, replaces
  exactly the characters that were written, leaves unrelated text as it
  was, and keys the token by the canonical value, so `１２３４５６７８Ｚ`
  and `12345678Z` are one token; rehydration writes back the form first
  written, as for every other value. UTS #39 confusable skeletons are not
  used: they are meant only for comparing strings and map digits to
  letters.
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

| Capability                                       | Claude Code | OpenCode | ACS |
| ------------------------------------------------- | :---------: | :------: | :-: |
| Block or rewrite the typed prompt                 |     Yes     |   Yes    | Yes |
| Block or rewrite a tool call's arguments          |     Yes     |   Yes    | Yes |
| Redact or block a tool call's output               |     No      |   Yes    | Yes |
| Rewrite conversation history resent to the model   |     No      |   Yes    | No  |
| Rewrite the system prompt                          |     No      |   Yes    | No  |

The ACS column covers the hooks veil maps (see
[Serving the Agent Control Standard](#serving-the-agent-control-standard-acs)).
No ACS 0.1.0 hook carries the history or system prompt resent to the
model, so those rows stay No.

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

The full list of what veil does not protect against, who owns each
residual risk, and the test behind every claim it does make is in the
[threat model](docs/threat-model.md) (LINDDUN and STRIDE over a data-flow
diagram of veil as a guard). The limits you are most likely to hit:

- **Claude Code: no output, history or system-prompt redaction.** The host
  has no hook for them (threat model DD1).
- **Detection is pattern-based.** veil detects Spanish DNI/NIE, IBAN,
  email, Spanish phone numbers, sensitive file paths, an optional client
  name catalog, and unscannable binary/base64 output, which it denies. It
  is not a general-purpose PII scanner: unstructured data is missed
  (threat model L4, I4; NER under study in #3).
- **The chat still shows tokens.** No hook rewrites the model's own reply
  as it is displayed, so an echoed `[DNI-001]` appears as the token.
- **Egress that bypasses veil is the host's job** (HCS-0008-R019; threat
  model DD2).
- **Losing the store directory loses the mapping.** veil then mints
  tokens from `-001` again for anything seen again: it never reuses a
  stale numbering, but it no longer knows what an earlier `[DNI-001]`
  meant (see [The pseudonym store](#the-pseudonym-store)).

## The pseudonym store

This is **pseudonymisation** in the sense of GDPR art. 4(5) and ISO/IEC
20889, not anonymisation: the text the model sees is still personal data,
and the store is the "additional information" that has to be kept
separately, under technical measures. veil keeps it encrypted at rest.

### Format

Each session is one [age v1](https://c2sp.org/age) file
(`age-encryption.org/v1`, Go library `filippo.io/age`) at
`<state>/veil/sessions/ids/<stem>.age` (see [File names](#file-names)), mode 0600, encrypted to one X25519
recipient. The plaintext inside is a JSON mapping (`"version": 2`): each
marker's canonical key and, when it differs, the first written form it
rehydrates to (the optional `written` member; a file without it, written
by an earlier veil, rehydrates each marker to its key). No real
value and no `category:original` key is on disk in clear. Writes go
through a new temp file (created with `O_EXCL`, mode 0600, after removing
any leftover or planted link), `fsync`, a rename and an `fsync` of the
directory, so a write is durable when it returns, even across a power
loss. A sibling `<stem>.lock` serializes writers across
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

### File names

A session id names its files injectively, so two distinct session ids
never share a mapping, a counters file or a `forget`:

- The stem is the session id's bytes in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)
  base32 (section 6), **lowercase and without padding**: `sess-1` is
  `onsxg4znge`. Base32 is single-case, so a case-insensitive
  filesystem (macOS, Windows) cannot fold two stems into one, and it never
  yields a path separator, a `.` or a Windows device name.
- An id whose base32 form is longer than 160 characters (an id over 100
  bytes) would not fit the filesystem's name limit (255 bytes) with its
  suffix. Its stem is the base32 of its first 60 bytes, `-`, and the
  base32 of the SHA-256 of the whole id; a plaintext `<stem>.id` file,
  written before anything else and kept like the counters file, holds the
  id so `find` and `sweep` can report it.
- **An empty or missing session id fails closed** with
  `VEIL_SESSION_ID_MISSING` on every host, as soon as the event needs a
  pseudonym (a rewrite or a rehydration). There is no shared bucket: an
  event without a session id that needs no pseudonym is still decided,
  since it links nothing. (ACS requests cannot omit it: the schema
  requires `metadata.session_id` as a UUID, so such a request is refused
  with `VEIL_ACS_REQUEST_INVALID`.)

Every report (`find`, `sweep`) names the session id the host used, never a
file stem. See [Migration from the lossy file names](#migration-from-the-lossy-file-names)
for stores written before this naming.

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
| Event needs a pseudonym but has no session id | `VEIL_SESSION_ID_MISSING` |

### Commands

Hosts read and delete a session's pseudonyms through veil, not by parsing
or removing its files:

```sh
veil store reveal <session>          # stdout: {"markers":[{"marker":"[DNI-001]","category":"DNI","value":"12345678Z"}]}
veil store forget <session> [...]    # removes each session's store and its lock
veil store forget --legacy-stem <stem> [...]  # removes a shared pre-#26 store
veil store find --value <value|->    # stdout: {"sessions":[{"session":"sess-1","categories":["DNI"]}]}
veil store sweep                     # stdout: {"forgotten":["sess-0"],"skipped":[],"failed":[],"legacy_stems":{"forgotten":[],"skipped":[],"failed":[]}}
```

- `reveal` prints every marker of the session and the real value it
  stands for (its canonical key, e.g. `12345678Z`; a write rehydrates the
  form first written), sorted by category and number, for a host's own "what veil
  hid" view. It needs the key, like any read. An unknown session prints
  `{"markers":[]}`.
- `forget` removes each named session's age file, any v1 file, any
  interrupted write (v1 or v2 temp file) and its lock, holding the lock
  while it deletes. It keeps the session's counters file, which holds no
  personal data, so the session id never reuses a marker number (see
  [Retention](#retention-and-data-subject-requests)). It needs no key, on purpose: a lost key must never
  block an erasure, and without the key the file is unreadable anyway. An
  unknown session succeeds. It reaches only that session id's files.
  **The session id itself outlives `forget`:** a file stem is the id in
  base32, which anyone can decode, and the counters file (and, for a long
  id, the `.id` file) stays. Hosts must not put personal data in session
  ids; use random ones such as UUIDs.
  `forget --legacy-stem <stem>` does the same for a store left under a
  shared pre-#26 name (see [Migration](#migration-from-the-lossy-file-names));
  a stem that is not a plain file name is bad usage.
- `find` lists the sessions whose store holds a value, and the categories
  it was hidden under; it never prints the value or any other value. A
  shared pre-#26 store is listed as `{"legacy_stem":"a_b","categories":[...]}`
  with no `session`, since its session id cannot be known. See
  [Retention and data subject requests](#retention-and-data-subject-requests).
- `sweep` removes the sessions unused for longer than the policy's
  `store.ttl`. See below. Shared pre-#26 stores are reported apart, under
  `legacy_stems`, by their stem. A file in `ids/` whose name maps to no
  session id (tampered, or a long id whose `.id` file is gone) is
  reported under `failed` as `ids/<stem>` with `VEIL_STORE_CORRUPT`, and
  the sweep goes on with the others; `find` fails closed on it instead.
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
  every session keeps a counters file, `<stem>.ctr`, which sweep and
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
  phone with spaces, dots or dashes matches its compact form. A phone
  matches by its E.164 form, so `612345678`, `+34 612 345 678` and
  `0034612345678` find the same sessions; the bare form typed as is
  also finds a session keyed before phones were keyed as E.164 (search
  with the bare nine digits to cover those).
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

### Migration from the lossy file names

**Store format change.** veil before #26 named a session's files
`<state>/veil/sessions/<stem>.*` with a lossy stem: `/`, `\` and `..`
became `_`, and an empty id became `unknown-session`, so `a/b`, `a\b`,
`a..b` and `a_b` shared one store. veil now carries such files over the
first time a session id is used, under the session's lock and then the
old lock name (`<stem>.json.lock`), with no command to run:

- **A stem only one id can have produced** (no `_`, not
  `unknown-session`, which covers UUIDs such as Claude Code's and ACS's)
  is that session's. Its counters, age and v1 files are renamed into
  `ids/` one by one, interrupted writes are removed and both directories
  are synced. Its markers keep rehydrating and numbering carries on; a
  crash midway is finished by the next use. A file already at its new name
  while the old one is still there is never overwritten or merged: the
  session fails closed with `VEIL_STORE_CORRUPT`.
- **A stem several ids could have produced** (with `_`, such as
  OpenCode's `ses_…` ids, or `unknown-session`) is **never read for any of
  them**, since it may mix sessions. It stays where it is, under its old
  name: `find` lists it as a `legacy_stem`, `forget --legacy-stem <stem>`
  erases it and retention sweeps it. Only its counters cross over: before
  each of those ids first mints, its counters start from the old stem's
  (its counters file, else the counts inside its mapping, which needs the
  key), so no marker number the host history may hold is ever reused. A
  retired stem retires those ids (`VEIL_SESSION_RETIRED`), and counters
  that cannot be read fail closed. The cost is that markers minted before
  the upgrade in such a session no longer rehydrate: they stay as they
  are, never resolved to another session's value.

Stop every older veil before the first new one runs (see Format): an
older veil does not know `ids/`.

On a case-insensitive filesystem (the macOS and Windows defaults), two
session ids that differ only in case (`Sess-1`, `sess-1`) already shared
one legacy file before #26, and the stem cannot tell which wrote it: the
first of them used after the upgrade adopts it, and the other starts
empty, with no counters. New files never fold (base32 is single-case);
this only concerns stores written before, by hosts whose ids differ only
in case.

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

The store's rows (DD4, DD5, T1 to T3, T8, T9, DOS1, DOS4) are part of the
whole [threat model](docs/threat-model.md).

## Configuring the name catalog

Set `VEIL_CATALOG` to a file listing client and worker names — either a
JSON array of strings, or one name per line:

```json
["María Pérez", "Juan García"]
```

Matching is whole-word, and both case- and accent-insensitive (`MARIA
PEREZ`, `maria perez`, and `María Pérez` all match the same catalog
entry), and so are full-width and decomposed forms (`Ｍａｒíａ`, or `Mari`
plus a combining acute accent plus `a`), keyed by the canonical `María`.
A catalog name joined to another name part by a hyphen or an apostrophe
is replaced whole: `Juan García-López` and `Ana-María Pérez` are one token each, keyed by the whole written name, so no part of the
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
(`.github/workflows/release.yml`; [GoReleaser](https://goreleaser.com/)
builds the binaries from [`.goreleaser.yaml`](.goreleaser.yaml)). What changed in each release, including
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

### Reproducing a release build

The binaries are reproducible, but byte identity holds only for **the same
commit built with the same Go version**, the two values `go version -m`
reports for a release asset: the Go version on its first line and the commit
in `vcs.revision`. Built that way from a clean checkout, the binary has the
same bytes (`-trimpath`, no build time or path in it); a different Go
version or commit gives different bytes. To rebuild one and compare it with
the release's `SHA256SUMS`:

```bash
TAG=v0.3.0
go version -m veil-linux-amd64 | head -1               # "veil-linux-amd64: go1.X.Y"
go version -m veil-linux-amd64 | grep vcs.revision     # the commit it was built from
GO_VERSION=go1.X.Y                                     # the version printed above
git clone --branch "$TAG" https://github.com/FullFran/veil veil-src
git -C veil-src rev-parse HEAD                         # must equal vcs.revision
(cd veil-src && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN="$GO_VERSION" \
  go build -trimpath -ldflags "-s -w" -o ../rebuilt ./cmd/veil)
sha256sum rebuilt veil-linux-amd64                     # the two digests match
```

Build from a checkout with no untracked files: Go records whether the tree
was modified (`vcs.modified`) in the binary, and a modified tree gives
different bytes. How a release is cut is in [`docs/releasing.md`](docs/releasing.md).

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
| `CREDENTIALS_DIRECTORY` | the `veil` binary (`cmd/veil`) | Set by systemd; veil reads its `veil-store-key` credential (and `veil-acs-key` in `veil acs`). |
| `VEIL_ACS_KEY_ID` | the `veil` binary (`veil acs`) | `key_id` of the ACS HMAC secret. See [Signatures](#signatures). |
| `VEIL_ACS_KEY_FD` | the `veil` binary (`veil acs`) | Number of an inherited descriptor holding the ACS secret (base64). |
| `VEIL_TIMEOUT_MS` | `adapters/opencode/veil-plugin.js` | Milliseconds to wait for one `veil` answer before failing closed. Defaults to 30000. |

The plugin reads answers up to 64 MiB and never waits forever. When it
fails closed it throws an `Error` carrying the problem's `code` and `type`
(see [Failures](#failures)): its own `VEIL_OUTPUT_TOO_LARGE`,
`VEIL_TIMEOUT` or `VEIL_UNAVAILABLE`, or the binary's code forwarded
unchanged. On `tool.execute.after`, where throwing blocks nothing, it
replaces the tool output with a notice naming the code instead.

## Serving the Agent Control Standard (ACS)

`veil acs` makes veil a Guardian Agent for any agent framework that speaks
the [OWASP Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard)
(ACS) over stdio: the framework (the Observed Agent) asks veil before
any text from outside the model enters its context (a user message, an
inbound trigger, a retrieval, a tool result) and before each tool call,
and veil answers allow, deny or modify. It speaks ACS **0.1.0**, pinned to an upstream commit with every
vendored file's sha256 (`internal/hosts/acs/v0_1/spec/`, see its
`SOURCE.md`).

```sh
veil acs < request.json     # one bare JSON-RPC 2.0 request, answered on one line
veil acs                    # or a stream of Content-Length framed messages until EOF
```

Every message is JSON-RPC 2.0 with the ACS envelope. veil validates each
request against the pinned JSON Schemas (with `uuid` and `date-time`
formats asserted) before reading it, and each response it writes
validates against the pinned response schema (the tests check this on
every vendored example).

> [!IMPORTANT]
> **Hosts must complete the handshake and set `on_decision_failure: deny`.**
> ACS has the Observed Agent apply its `on_decision_failure` posture to any
> JSON-RPC error, and that posture defaults to `proceed`. veil answers
> every refusal it can as a deny decision (see
> [Failing closed](#failing-closed)), but a few requests carry no id or
> version a decision could answer, and those stay JSON-RPC errors. veil
> keeps no handshake state, so it cannot see whether the host completed
> `handshake/hello` or kept the default: a host that skips the handshake
> or proceeds on failure lets those requests through.

### Mapping

| ACS | veil |
| --- | --- |
| `steps/agentTrigger`, `steps/userMessage` | `PromptSubmit` event |
| `steps/knowledgeRetrieval`, `steps/memoryContextRetrieval` | `ToolOutput` event, tool `knowledgeRetrieval` or `memoryContextRetrieval` |
| `steps/toolCallRequest` | `ToolArgs` event, tool `tool.name`, arguments the unwrapped `arguments.<name>.value` |
| `steps/toolCallResult` | `ToolOutput` event, tool `tool.name` |
| `metadata.session_id` | the pseudonym session |
| Allow | `allow` |
| Deny | `deny`, the policy's reason in `reasoning` |
| Rewrite of an argument value | `modify` with `parameter_overrides` of that argument, its whole value rebuilt |
| Rewrite of anything else in the payload | `modify` with `redactions`, one JSON pointer into the payload per changed value (`/content/0/value`, `/query/value`, `/intent/goal`, `/arguments/a/provenance/...`) |
| Rewrite veil cannot express | `deny` with `VEIL_ACS_UNREDACTABLE` (below) |
| Decision evidence | `policy_data.veil.evidence`, the same record as [Decision evidence](#decision-evidence) |
| `handshake/hello` | `ServerHello`: `negotiated_version` `0.1.0`, `methods_evaluated` = the six hooks above that the client implements, in that order, `on_decision_failure` `deny`, `skew_window_ms` 300000 |
| `system/ping` | always `allow` with `payload.status` `ok`, never a signature requirement |
| Any other method | error -32003 `VEIL_ACS_METHOD_UNSUPPORTED` |

**What veil scans.** Whatever the hook, the event's fields are every
string, number and boolean in `params` and every member name, each named
by its JSON pointer under `params` (`/payload/arguments/path/value`,
`/metadata/agent_id`; a member name as `key /payload/arguments/path`).
Detectors see every piece of text the request carries, extra members
included, not a list of fields. Only the members veil reads itself are
left out: `acs_version`, `request_id`, `timestamp`, `signature` and
`metadata.session_id`. When the policy would pseudonymize a value ACS
cannot carry a replacement for, veil denies the step with
`VEIL_ACS_UNREDACTABLE`: a member name, anything outside the payload
(metadata, extra `params` members), `tool.name` (it selects what runs),
`raw_command` (a host may execute it instead of the structured
arguments), or an argument that would need both an override and a
redaction.

veil never answers `ask` or `defer`. It has no channel to a human approver,
and only the host may collect an approval (HCS-0005-R014, R015); a
decision veil cannot express, or a rewrite that changes nothing, is a
deny.

### Failing closed

veil reads every request with a strict parser before anything else. A
member name repeated in one object, a member name that differs from
another in the same object only by case, or a string with invalid UTF-8
or a lone surrogate escape (`\ud800`) is refused: those are documents two
parsers read differently (a case-insensitive decoder merges `value` and
`VALUE`), so the schema, the signature and veil must never see one and
the host another.

On an evaluated hook, a refusal is a **deny decision**, not an error: the
code in `reason_codes`, the problem in `policy_data.veil.problem`, and,
when veil holds the ACS key, signed with the request's session key even
though the request itself did not verify (a host that requires signed
responses would otherwise treat it as a failure). An error carries no decision, and ACS section 6.4 has the
Observed Agent apply `on_decision_failure` to it, whose default is to
proceed; a decision is always honoured. The same holds for a valid hook
veil cannot decide (invalid policy, store, evidence or secret
configuration) and for `VEIL_ACS_UNREDACTABLE`.

| Condition | Answer on an evaluated hook | JSON-RPC code otherwise | veil code |
| --- | --- | --- | --- |
| Not JSON | error | -32700 | `VEIL_INPUT_INVALID` |
| Batch, or the root not an object | error | -32600 | `VEIL_ACS_REQUEST_INVALID` |
| Ambiguous member or string outside `params.payload`, `params.metadata` and `params.signature` (the id or method cannot be trusted) | error, no id | -32600 | `VEIL_ACS_REQUEST_INVALID` |
| Ambiguous member or string inside them, or envelope off the schema | deny | -32600 | `VEIL_ACS_REQUEST_INVALID` |
| Payload off its method's schema | deny | -32602 | `VEIL_ACS_REQUEST_INVALID` |
| No `acs_version`, or one veil has no package for (`data.supported_versions`) | error | -32600, -32001 | `VEIL_ACS_REQUEST_INVALID`, `VEIL_ACS_VERSION_UNSUPPORTED` |
| Method veil does not evaluate | error | -32003 | `VEIL_ACS_METHOD_UNSUPPORTED` |
| Signature missing, unexpected, of another algorithm or `key_id`, or wrong | deny | -32004 | `VEIL_ACS_SIGNATURE_INVALID` |
| `request_id` already seen in the session | deny | -32005 | `VEIL_ACS_REPLAY` |
| `timestamp` more than 5 minutes off (`data.skew_window_ms`) | deny | -32006 | `VEIL_ACS_TIMESTAMP_OUT_OF_WINDOW` |
| veil cannot evaluate, on `handshake/hello` | error | -32000 | the cause (e.g. `VEIL_POLICY_INVALID`) |

A deny needs an `id` that is a string or a number and a `request_id`
that is a uuid; when the request has neither, the refusal stays the
error. An error's `data` carries `reason` (the veil code), `message` (its
title) and `problem` (the [RFC 9457 problem](#failures)). Every row that
stays an error is why the host must honour `on_decision_failure: deny`.

In every case veil also writes the problem line on stderr and exits 1
once the input ends; stdout holds the JSON-RPC answers.

### Signatures

Signing is optional and out of band, like the store key. Set
`VEIL_ACS_KEY_ID` and give the secret, base64 encoded and at least 32
bytes once decoded, on an inherited descriptor named by `VEIL_ACS_KEY_FD`
or as the systemd credential `veil-acs-key`. The key never comes from a
message.

- With a secret, every request but `system/ping` must carry an
  `HMAC-SHA256` signature with that `key_id`, over the RFC 8785 (JCS)
  form of the request without `params.signature`, under the per-session
  key HKDF-SHA256(secret, no salt, info = `session_id`, 32 bytes) of ACS
  section 10. Responses to verified requests are signed the same way in
  `result.signature`.
- Without one, signed requests are refused: their `key_id` names no key
  veil holds.
- A key id without a secret, a secret without a key id, or a secret that
  is not base64 or is too short fails closed with `VEIL_ACS_KEY_INVALID`.

The JCS and HMAC implementation is checked against vectors produced by
the `rfc8785` package the ACS reference adapters use
(`internal/hosts/acs/v0_1/testdata/kat`), and the key derivation against
the specification's own example.

### Divergences from ACS 0.1.0

- **Fail closed.** veil advertises `on_decision_failure: deny` and answers
  a failure it can still express as a deny, where the reference Guardian
  defaults to proceed.
- **Exact versions.** Only `acs_version` `0.1.0` is accepted; 0.1.x patch
  releases rewrite the schemas in place, so no other version is assumed to
  match the pinned files.
- **No session chain.** veil keeps no `chain_hash` and needs no prior
  handshake; replays are detected only within one `veil acs` process, so
  a bare one-message invocation cannot detect them. A `request_id` is
  remembered until its timestamp leaves the 5-minute window (the
  timestamp check refuses it from then on), so memory stays bounded.
- **Six hooks.** veil evaluates every 0.1.0 hook whose payload carries
  text that enters the model's context from outside it, plus the tool
  call. ACS lets the Observed Agent treat a method missing from
  `methods_evaluated` as allowed, so the hooks left out are outside veil's
  guarantee, each for a reason:
  - `steps/agentResponse`: model output on its way to the user. It has
    already left the provider, so redacting it protects nothing from the
    provider; giving the user back the real values behind veil's
    pseudonyms is a separate feature, not a redaction.
  - `steps/sessionStart`: `user_identity` and `platform_context` describe
    the session to the Guardian and are not model input; its `intent` is
    carried again on `steps/agentTrigger`, the first content-bearing hook,
    which veil evaluates.
  - `steps/turnStart`, `steps/skillLoad`, `steps/preCompact`,
    `steps/subagentStop`, `steps/turnEnd`, `steps/sessionEnd`: identifiers,
    enums, digests and counts, no free text (the `summary` of the last
    three is audit only, model-generated, and decision-ineligible).
  - `steps/subagentStart`: `subagent_intent` is governance metadata for
    intent-based access control; the subagent's task reaches it through the
    delegating `steps/toolCallRequest` and its own session's hooks, which
    veil evaluates (an inference from the hook descriptions, not stated by
    the specification).
  - `steps/skillRegister`: the skill body is an author-supplied artifact,
    not user data, and its approval is bound to its digest, which a
    redaction would break.
  - `steps/postCompact`: the summary is model-generated from steps veil
    already evaluated.
  - `steps/memoryStore`: a write to the agent's memory, not the model; it
    reaches the model only through `steps/memoryContextRetrieval`.
  - `agbom/*`: component inventory, not model input.
  
  The acs-provenance variants of the evaluated hook schemas only make
  `provenance` required; the payload is the same, so veil validates every
  request against the base schema, which accepts both.
- **Non-text content.** Image, audio and file items of a user message are
  scanned only as the JSON value the client sends (a URL or encoded
  bytes); veil does not read text inside images or audio.
- **Redactions with the reference adapters.** The Python reference
  adapters at the pinned commit (Claude Code, Cursor, NVIDIA NAT) turn a
  `modify` carrying `redactions` into a deny because their hosts cannot
  apply one, so with them a veil rewrite blocks the step instead of
  pseudonymizing it. It never lets the value through.
- **HMAC only.** No asymmetric or post-quantum algorithms.
- **stdio only.** No HTTP transport.
- **OCSF trace mapping.** `trace/ocsf-mapping.json` is normative for a
  deployment that emits OCSF for the ACS Trace pillar: decisions as
  Detection Finding (2004), allows as Application Lifecycle (6002), joined
  by `unmapped.acs`. veil does not claim the Trace pillar. Its evidence in
  `policy_data.veil.evidence` is veil's own record, a Data Security
  Finding (2006), shared with every host. It agrees with the ACS mapping on
  `action_id` (allow 1, deny 2, modify 4) and `disposition_id` (allow 1,
  deny 2, modify 99) and on the severity of allow (1) and modify (2). It
  differs on the class, on the severity of deny (3, High, where ACS uses
  4), on the `disposition` caption of a rewrite (`Pseudonymized`, where
  ACS uses the disposition name), and it carries no `unmapped.acs` join
  fields. A Trace emitter can derive the ACS events from the response,
  which holds the `request_id`, decision and reasoning.
- **Strict JSON.** ACS does not forbid repeated or case-variant member
  names or lone surrogates; veil refuses them (above), and its JCS
  rejects lone surrogates as RFC 8785 requires.
- **Integers.** Like the `rfc8785` reference, integer literals of
  magnitude 2^53 or more cannot be signed; such a signed request is
  refused.

Unverified: which document a `redactions` pointer is relative to is not
normative in 0.1.0. veil follows the reference AGT adapter, where pointers
on a tool result address the payload (`/outputs/0/value`), and applies the
same rule to every hook.

### Pinning a new ACS version

1. Create `internal/hosts/acs/vX_Y/` as a sibling of `v0_1`: copy the
   new release's schemas, `LICENSE`, `NOTICE` and the examples unedited
   into `vX_Y/spec/`, with a `SOURCE.md` naming the upstream commit.
2. Regenerate the digests from inside `spec/`:
   `find . -type f ! -name SOURCE.md ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS`.
3. Implement `port.Version` there (start from a copy of `v0_1`) and add
   one entry to `versions` in `internal/hosts/acs/acs.go`.
4. Run `go test ./internal/hosts/acs/...`: the pin test, the example
   decoding and the response schema checks must pass for the new package.

Dropping a version is deleting its folder and its entry; `internal/domain`
never sees any of it (`TestDomainImportsNoHostAdapter`).

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
written as a single JSON line on stderr (nothing on stdout, except in
`veil acs`, where stdout carries the JSON-RPC answer):

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
| `VEIL_SESSION_ID_MISSING` | `session-id-missing` | The event needs a pseudonym but carries no session id; veil never shares one mapping between events without a session |
| `VEIL_STORE_IO` | `store-io` | The pseudonym store cannot be read or written |
| `VEIL_EVIDENCE_WRITE` | `evidence-write` | `VEIL_EVIDENCE_FILE` is set and the evidence record cannot be appended |
| `VEIL_CATALOG_REVISION_INVALID` | `catalog-revision-invalid` | `VEIL_CATALOG_REVISION` is not an opaque token (`[A-Za-z0-9._:-]{1,128}`) |
| `VEIL_ACS_VERSION_UNSUPPORTED` | `acs-version-unsupported` | `veil acs`: the message's `acs_version` has no adapter |
| `VEIL_ACS_REQUEST_INVALID` | `acs-request-invalid` | `veil acs`: a batch, or a message off the pinned ACS schema |
| `VEIL_ACS_METHOD_UNSUPPORTED` | `acs-method-unsupported` | `veil acs`: a method veil does not evaluate |
| `VEIL_ACS_SIGNATURE_INVALID` | `acs-signature-invalid` | `veil acs`: signature missing, unexpected, of an unknown `key_id` or algorithm, or wrong |
| `VEIL_ACS_REPLAY` | `acs-replay` | `veil acs`: `request_id` already seen in the session |
| `VEIL_ACS_TIMESTAMP_OUT_OF_WINDOW` | `acs-timestamp-out-of-window` | `veil acs`: `timestamp` outside the 5-minute window |
| `VEIL_ACS_KEY_INVALID` | `acs-key-invalid` | `veil acs`: the secret configuration is incomplete, unreadable, not base64 or under 32 bytes |
| `VEIL_ACS_UNREDACTABLE` | `acs-unredactable` | `veil acs`: data veil would pseudonymize sits where no ACS modification can be trusted to replace it (a member name, metadata, `tool.name`, `raw_command`), so the step is denied |
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
  next to Unicode, names outside the catalog, nested tool arguments, and
  Unicode lookalikes (full-width forms, zero-width and other format
  characters, no-break spaces, digits of other scripts).
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

The baseline at the time of writing (90 cases, default policy):

| label | tp | fp | fn | precision | recall | f1 |
| --- | --: | --: | --: | --: | --: | --: |
| DNI | 23 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| IBAN | 13 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| EMAIL | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| TEL | 22 | 3 | 0 | 0.8800 | 1.0000 | 0.9362 |
| NOMBRE | 14 | 1 | 2 | 0.9333 | 0.8750 | 0.9032 |
| micro | 84 | 4 | 2 | 0.9545 | 0.9767 | 0.9655 |

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
workflows (`.github/workflows/codeql.yml`).

Every parser of untrusted input has a native Go fuzz test (`func FuzzXxx`):
the Claude Code and OpenCode pipelines (decode, policy, encode; a rewrite
never sends back a found value), ACS JSON-RPC answers and stdio framing, the
policy parser, the detectors and the flatten/rebuild of tool arguments, and
the store's session-file decryption, key parsing and file naming.
Their seed corpora run with `go test`; `.github/workflows/fuzz.yml` fuzzes
each target for 15 seconds on every pull request and push to `main`, and for
3 minutes weekly. To fuzz one target locally:

```bash
go test -run '^$' -fuzz '^FuzzPipeline$' -fuzztime 60s -fuzzminimizetime 5s ./internal/hosts/claudecode
```

A failing input is written to the package's `testdata/fuzz/<Target>/`;
commit it with the fix so it stays a regression test. The
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
