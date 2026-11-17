# Governance

veil is a single-maintainer project. This document says who decides what,
how, and what happens if the maintainer is unavailable.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| Maintainer | Fran ([@FullFran](https://github.com/FullFran)) | Sets the [roadmap](ROADMAP.md); reviews and merges pull requests; triages issues; handles vulnerability reports ([SECURITY.md](.github/SECURITY.md)); cuts releases ([docs/releasing.md](docs/releasing.md)); enforces the [code of conduct](CODE_OF_CONDUCT.md); owns the repository settings and the OpenSSF Best Practices entry. |
| Contributor | Anyone who opens an issue or a pull request | Follows [CONTRIBUTING.md](.github/CONTRIBUTING.md) and the code of conduct. |
| Reporter | Anyone who reports a vulnerability privately | Follows [SECURITY.md](.github/SECURITY.md); is credited in the advisory and the changelog unless they ask not to be. |

## How decisions are made

- Day-to-day changes are decided in their pull request: a change is merged
  when its checks pass and the maintainer approves it against the review
  standards in [CONTRIBUTING.md](.github/CONTRIBUTING.md#code-review).
- Changes to behaviour a host consumes (commands, exit codes, failure types,
  the policy schema, the store format) are proposed in an issue first and
  marked **Breaking** in the [changelog](CHANGELOG.md) with what a host must do.
- Disagreements are discussed in the issue or pull request, in public. The
  maintainer makes the final call and writes down the reason there.

## Becoming a maintainer

A contributor with a record of reviewed, merged pull requests can be invited
by the maintainer to become a second maintainer, with write access and a
share of the review load. The invitation, and this document's update, happen
in a public pull request.

## Continuity

All code, issues, decisions and release automation live in the public GitHub
repository, and releases are signed keylessly by the release workflow, so no
private key or undocumented step is needed to continue the project. If the
maintainer is unreachable for more than 90 days, anyone may fork it under the
[Apache-2.0 license](LICENSE); release artifacts of a fork are signed with
the fork's own workflow identity. Giving a second person administrative
access to the repository (so the project itself, not only a fork, continues)
is an open item for the maintainer.
