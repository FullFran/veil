# OpenCode acceptance test

This is veil's end-to-end acceptance test for the OpenCode anonymizer. It
drives a real, installed OpenCode CLI against a local mock OpenAI-compatible
HTTP server (never a real model provider), with veil's real plugin
(`adapters/opencode/veil-plugin.js`) and a freshly built `veil` binary
wired in through an isolated `XDG_CONFIG_HOME` / `XDG_DATA_HOME` /
`XDG_CACHE_HOME` / `XDG_STATE_HOME`, so it never touches your real
OpenCode configuration, sessions, or pseudonym state.

## What it proves

1. A DNI, IBAN, email, phone number, and catalog name (`María Pérez`,
   from `fixtures/catalog.json`) typed directly into a prompt never reach
   the mock provider.
2. The same fixture (`fixtures/client-notes.txt`), read from disk by the
   agent, never reaches the mock provider either.
3. A file the agent writes, even one whose content the model only ever
   saw as pseudonym tokens (e.g. `[DNI-001]`), ends up holding the real
   values on disk (rehydration), and that a later conversation turn does
   NOT quietly leak those same real values back to the model out of the
   tool call's own recorded history.
4. Forcing the anonymizer itself to fail (an invalid `VEIL_CATALOG`)
   blocks the request instead of quietly letting the prompt through
   unfiltered: veil's fail-closed contract.

## Prerequisites

- Go (to build the `veil` binary from this repo).
- Node.js (to run the mock provider and the test script itself).
- `opencode` on your `PATH`. This test was built and verified against
  **OpenCode 1.18.32**; run `opencode --version` to check yours.
- Network access the first time you run this: OpenCode resolves the
  `@ai-sdk/openai-compatible` provider package via its own package
  manager, which needs to fetch it once (and caches it after that).

## Running it

```bash
node test/e2e/opencode/run.mjs
```

The script builds `veil`, starts the mock provider on a random free port,
writes an isolated OpenCode config pointing at both, runs the four
scenarios above with `opencode run --dir <scratch-project>`, and asserts
on the mock's own request log (and, for scenario 3, on the file OpenCode
actually wrote). It prints `PASS`/`FAIL` per check and exits non-zero if
anything failed.

On success, it deletes its scratch directory. On failure, it leaves the
scratch directory in place and prints its path, so you can inspect
`requests.log` (every request the mock received, one JSON line each) or
the project directory's own files.

## Files

- `run.mjs` — the orchestrator: builds veil, starts the mock, runs each
  scenario, and asserts.
- `mock-server.js` — the local OpenAI-compatible mock. Its scripted
  behavior is selected by a marker in the first user message
  (`[SCENARIO_PROMPT]`, `[SCENARIO_READ]`, `[SCENARIO_WRITE]`); see the
  comment at the top of that file for the exact script per marker.
- `fixtures/client-notes.txt` — a synthetic client record with a valid
  Spanish DNI, IBAN, email, phone number, and a catalog name.
- `fixtures/catalog.json` — the matching `VEIL_CATALOG` file.

## Why not Go tests for this

The domain and host-adapter logic already has thorough Go unit and
round-trip tests (`go test ./...`). What only an end-to-end run like this
one can prove is that OpenCode's actual, installed plugin loader and hook
signatures still behave the way veil's design assumes — the whole reason
this repo has a spike-and-verify step (see `integration notes`'s T1
findings in the `downstream harness` repo) before building on any of this.
