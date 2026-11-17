# Security policy

veil is a privacy guard: a bug that lets personal data or a secret leave the
machine unredacted, or that makes veil allow an event it should deny, is a
security vulnerability.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/FullFran/veil/security/advisories/new>.

Do not open a public issue, pull request or discussion for it. Include the
veil version (`veil-*` release asset or commit), the host (Claude Code or
OpenCode) and the smallest event payload that shows the problem. Use made-up
data in the report, never real personal data.

You will get an acknowledgement in the advisory thread. The fix is developed
in a private fork of the advisory, released, and the advisory is then
published with credit to the reporter unless they prefer otherwise.

## Supported versions

Only the latest release receives fixes.

## Threat model

See the [threat model](../docs/threat-model.md).

## Verifying a release

Releases built by the current release workflow carry SLSA build provenance
and a Sigstore signature.
See "Verifying a release" in the [README](../README.md#verifying-a-release).
