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
description of something it is about to do: a typed prompt, or a tool
call's arguments. veil runs that event through a set of detectors (a
Spanish DNI/NIE detector, a sensitive-file-path detector) and returns
Allow, Deny, or Rewrite.

The domain logic in `internal/domain` has zero knowledge of which host
produced an event. Only the two adapter packages,
`internal/hosts/claudecode` and `internal/hosts/opencode`, know how to
speak each host's wire format.

## The capability matrix

The two hosts have genuinely different hook/plugin capabilities. This is
not a limitation of veil's implementation; it is a limitation of what
each host exposes. The matrix below is enforced in code
(`internal/domain/capability.go`), not just documented here: asking veil
to enforce a guarantee a host cannot provide returns an explicit
`UnsupportedCapabilityError`, never a silent allow.

| Capability                                    | Claude Code | OpenCode |
| ---------------------------------------------- | :---------: | :------: |
| Block or rewrite the typed prompt              |     Yes     |    No    |
| Block or rewrite a tool call's arguments       |     Yes     |   Yes    |
| Redact or block a tool call's output           |     No      |    No    |

Why:

- **Claude Code** hooks run as external processes. `UserPromptSubmit`
  fires on the typed prompt before the model sees it and can block (exit
  code 2) or rewrite it. `PreToolUse` fires before a tool call and can
  block or rewrite its arguments. `PostToolUse` is observe-only: it
  cannot block or redact a tool's output, only attach additional context.
- **OpenCode** plugins are in-process JS/TS modules. `tool.execute.before`
  can block (by throwing) or rewrite (by mutating `output.args`) a tool
  call's arguments. There is no documented hook that reaches the user's
  typed prompt at all. `tool.execute.after` exists, but whether it can
  mutate the tool's result is unverified, so veil treats it as
  unsupported rather than assuming it works.

The only guarantee both hosts share is inspecting and blocking/rewriting
tool call arguments before execution. Prompt-level enforcement exists
only on Claude Code.

## What this cannot do

- **OpenCode: no prompt-level enforcement at all.** There is no hook that
  reaches the user's typed prompt on OpenCode. If you ask veil to
  evaluate a prompt-level event on OpenCode, it returns an explicit
  `UnsupportedCapabilityError` instead of pretending to protect you.
  There is no workaround for this within OpenCode's current plugin API.
- **Claude Code: no output redaction.** `PostToolUse` cannot block or
  redact what a tool already returned. If a tool call itself was allowed,
  its output is not filtered by veil.
- **OpenCode: no verified output redaction either.** `tool.execute.after`
  might be able to mutate a tool's result, but this is unverified upstream
  behavior. veil does not build on it and treats it as unsupported.
- veil only ships two detectors today: a Spanish DNI/NIE detector and a
  sensitive-file-path detector (`.env`, SSH private keys, and similar).
  It is not a general-purpose PII scanner.

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
the hook's JSON payload on stdin.

## Installing on OpenCode

Build the binary, then wire the shim plugin in `adapters/opencode`:

```bash
go build -o /usr/local/bin/veil ./cmd/veil
```

Register `adapters/opencode/veil-plugin.js` as an OpenCode plugin per your
OpenCode configuration. The shim spawns the `veil` binary (or the path in
`VEIL_BINARY`) with the `opencode` argument for every `tool.execute.before`
call, and throws to block or mutates `output.args` to rewrite, based on
veil's response. Since OpenCode has no prompt-level hook, there is nothing
to wire up for prompt enforcement on this host: see "What this cannot do"
above.

## Development

```bash
go test ./...
go vet ./...
gofmt -l .
```

This project is built test-first: every detector, every host adapter, and
the capability matrix itself has a test that was written and observed to
fail before the corresponding implementation was written. See
`internal/domain/leak_test.go` for the headline suite proving the guard
can actually go red, including the capability-error test for OpenCode
prompt enforcement, which is the most important test in the repository.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
