# Architecture

veil is one Go binary with no network access. A host (Claude Code, OpenCode,
or any ACS client) runs it once per event: it reads one JSON message on
stdin, decides, and answers on stdout with an exit code. Nothing stays
running between events except the encrypted pseudonym store on disk.

```text
 host (Claude Code hook / OpenCode plugin / ACS client)
   │ JSON event on stdin              ▲ answer on stdout, exit code
   ▼                                  │ (failure: RFC 9457 line on stderr)
 cmd/veil ── chooses the host adapter by subcommand, loads the policy
   │
   ├── internal/hosts/{claudecode,opencode,acs}  decode the host's JSON into a
   │                                             domain.Event; encode the Decision
   ├── internal/policy        the declarative policy (JSON Schema 2020-12),
   │                          which builds the detector registry
   ├── internal/domain        host-agnostic logic: detectors, Policy.Evaluate
   │                          (allow / deny / rewrite), pseudonyms, rehydration
   ├── internal/pseudonymstore  the store port's file adapter: one age-encrypted
   │                            file per session, kernel locks, key sources
   ├── internal/evidence      one CloudEvents/OCSF record per decision, no data
   └── internal/problem       the failure registry (stable type and code)
```

## Components

| Component | Responsibility | Depends on |
|---|---|---|
| `cmd/veil` | Wiring: subcommands (`claude-code`, `opencode`, `acs`, `policy`, `store`), environment, exit codes | everything below |
| `internal/hosts/*` | One adapter per host: its JSON contract in and out, nothing else | `domain` (and `problem` for ACS) |
| `internal/domain` | Detection, the decision, pseudonym minting and rehydration, through a `PseudonymStore` port | standard library and `golang.org/x/text` only |
| `internal/policy` | Parse and validate a policy file, compute its digest, build the registry | `domain`, `problem`, JSON Schema validator |
| `internal/pseudonymstore` | The file-backed store: format, file names, locks, keys, retention, migration | `domain`, `filippo.io/age`, `go-keyring` |
| `internal/evidence` | Decision evidence records | `domain` |
| `internal/problem` | Failure types and codes | standard library |
| `adapters/opencode` | JavaScript shim that runs `veil opencode` for each OpenCode hook | Node.js |
| `cmd/veil-eval`, `internal/eval` | Recall and latency against the evaluation corpus | `domain`, `policy` |

## Rules that keep it this shape

- **Ports and adapters.** `internal/domain` never imports a host adapter or
  the store implementation; `internal/domain/imports_test.go` fails the
  build if it does, and the archsieve gate in `ci.yml` fails a pull request
  that adds a new architecture error.
- **Fail closed.** Any error (input, policy, store, key, output) becomes a
  problem line and an exit code the host treats as "block"; there is no path
  where an error lets the original data through.
- **One event per process.** No daemon, no shared memory; concurrent hooks
  coordinate only through per-session kernel file locks.

Security properties and the threats they answer are in
[threat-model.md](threat-model.md) and [assurance-case.md](assurance-case.md).
