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

Contributions are licensed under the Apache License 2.0, as section 5 of
that license states, like the rest of the project.
