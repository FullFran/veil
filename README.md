# veil

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
  numbering.
- **Hard-deny** (a tool call targeting a known secrets-bearing file, or
  tool output veil cannot scan at all — see "Attachments and binary
  content" below): there is no safe rewrite, so the event is blocked
  outright, exactly as before.

Where a host can also write real data to disk (a `write`/`edit`/`patch`
tool call), veil rehydrates: any pseudonym token still present in that
call's arguments is turned back into the real value first, so the file on
disk holds real data, never a placeholder the model was shown instead of
it.

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
entry). If `VEIL_CATALOG` is set but cannot be read or parsed, veil fails
closed at startup: every event is blocked with an error rather than
silently running without the catalog. If `VEIL_CATALOG` is unset, the
name-catalog detector is simply not registered.

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

## Installing on OpenCode

Build the binary, then wire the shim plugin in `adapters/opencode`:

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
| `XDG_STATE_HOME`| the `veil` binary (`cmd/veil`)     | Base directory for the per-session pseudonym store. Falls back to the OS temp dir. |

## Development

```bash
go test ./...
go vet ./...
gofmt -l .
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
