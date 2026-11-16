# Vendored ACS v0.1.0 specification files

These files are copied unedited from the OWASP Agent Control Standard
repository. Do not edit them: bump the pin instead (see the README section
"Pinning a new ACS version").

- Repository: https://github.com/GenAI-Security-Project/agent-control-standard
  (formerly https://github.com/Agent-Control-Standard/ACS, which redirects)
- Commit: `db457a84393bd80954c9b70b2271a719bf7c61cd` (main, 2026-11-05)
- Wire version: `acs_version` `0.1.0`
- Licence: `schema/**`, `LICENSE` and `NOTICE` are Apache-2.0 (`specification/**`
  in the upstream `LICENSING.md`). The examples are code samples embedded in
  Markdown, which `LICENSING.md` also places under Apache-2.0.

Why a commit and not the `v0.1.4` tag: at `v0.1.4`, Specification section 10
says the HMAC key is HKDF-derived but fixes no salt, info or length and does
not define `key_id`. Commit `b6b2d75`, after the tag, defines both. The
upstream CHANGELOG also states that files under `/schema/v0.1.0/` change in
place across 0.1.x releases, so only a commit plus a digest identifies them.

`SHA256SUMS` holds the sha256 of every file here except this one and itself.
`go test ./internal/hosts/acs/...` checks it, so CI fails on any drift.

## Files

| Vendored path | Upstream path |
| --- | --- |
| `schema/*.json` | `specification/v0.1.0/<same name>` |
| `schema/hooks/*.json` | `specification/v0.1.0/hooks/<same name>` |
| `LICENSE`, `NOTICE` | `LICENSE`, `NOTICE` |

## Examples

Each example is the exact content of one fenced `json` block, lines as listed
(inclusive), with a trailing newline.

| Vendored path | Upstream path and lines |
| --- | --- |
| `examples/readme-file-read.request.json` | `README.md` 115-132 |
| `examples/readme-file-read.response.json` | `README.md` 138-147 |
| `examples/readme-database-query.request.json` | `README.md` 178-195 |
| `examples/readme-database-query.response.json` | `README.md` 199-214 |
| `examples/in-action-email-send.request.json` | `docs/topics/ACS_in_action_example.md` 43-83 |
| `examples/in-action-email-send.response.json` | `docs/topics/ACS_in_action_example.md` 91-116 |
| `examples/nat-tool-call-request.request.json` | `adapters/docs/nat/example_payloads.md` 91-111 |
| `examples/nat-tool-call-result.request.json` | `adapters/docs/nat/example_payloads.md` 117-139 |

The two `nat-*` examples carry a placeholder signature (`"<base64 HMAC>"`),
so they decode but never verify.
