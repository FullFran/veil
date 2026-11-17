# Contributing to veil

Bug reports and feature requests go to
[GitHub issues](https://github.com/FullFran/veil/issues). Security problems
do not: report them privately as [`SECURITY.md`](SECURITY.md) explains.

## Proposing a change

1. Open an issue first for anything beyond a small fix, so the design can be
   agreed before code is written.
2. Fork, create a branch, and open a pull request against `main`.
3. Write the test first and watch it fail on its assertion, then make it
   pass. Every new detector, host adapter behaviour or capability needs a
   test in the automated suite. Tests check codes and structure, not message
   text.
   Code that parses untrusted input (host JSON, policy, store files, keys)
   needs a native fuzz test (`func FuzzXxx(f *testing.F)`) asserting its
   invariants; see "Development" in the [README](../README.md#development).
4. Keep `internal/domain` free of host or transport types. CI fails if it
   depends on any `internal/hosts/...` package.
5. Update `README.md` for every new command, flag, environment variable or
   format.
6. Use [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `ci:`, ...).

## Checks

CI runs these on every pull request; run them locally first:

```bash
gofmt -l .                                            # must print nothing
go vet ./...
go test -count=1 ./...
node --test adapters/opencode/veil-plugin.test.mjs   # if you touched the plugin
```

CI also runs an architecture gate (`archsieve diff --fail-on error` between
the base and the head of the pull request); see "Development" in the
[README](../README.md#development) to run it locally.

CI also fails if statement coverage over the whole module drops below 80%
(`go test -coverpkg=./... -coverprofile=...`; the total is in the job
summary).

## Coding standards

- Go code follows [Effective Go](https://go.dev/doc/effective_go) and the
  [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments), is
  formatted with `gofmt`, and passes `go vet` and golangci-lint
  ([`.golangci.yml`](../.golangci.yml): the `standard` linters plus gosec).
  CI enforces all three. A gosec finding is fixed, or justified inline with
  `#nosec <rule> -- <reason>`.
- JavaScript (the OpenCode plugin) uses Node.js built-ins only and is tested
  with `node --test`.
- Comments say why, not what. Errors returned to hosts are problem codes
  from `internal/problem`, never free text with input in it.

## Bug fixes

Every bug fix comes with a regression test that fails without the fix. A
crash or wrong answer found by a fuzz target is committed as an input under
the package's `testdata/fuzz/<Target>/`.

## Code review

Every change to `main` goes through a pull request. Before approving, the
reviewer checks that:

- CI is green (formatting, vet, tests with the race detector, coverage,
  static analysis, vulnerability scans, the architecture gate);
- the change has the test that proves it, written first, and a regression
  test for a fix;
- no detected value, path or session id can reach stdout, stderr, logs or
  evidence in clear;
- every error path fails closed;
- new input from a host, a file or the environment is validated, and a new
  parser has a fuzz target;
- workflow changes pin actions by commit SHA and keep the default token
  read-only;
- README, CHANGELOG (`Unreleased`, with **Breaking** where a host must act)
  and the threat model are updated where the behaviour changes.

Reviews happen in the pull request, in public. The maintainer merges; see
[GOVERNANCE.md](../GOVERNANCE.md). Releases follow
[docs/releasing.md](../docs/releasing.md).

## License

Contributions are licensed under the Apache License 2.0, as section 5 of
that license states, like the rest of the project.
