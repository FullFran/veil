# Releasing veil

Only the maintainer cuts releases. A release is a `vMAJOR.MINOR.PATCH` tag
([Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)); while the
major version is 0, a minor version may break compatibility, and every such
change is marked **Breaking** in the changelog.

## Steps

1. On `main`, with CI green, rename `## [Unreleased]` in
   [`CHANGELOG.md`](../CHANGELOG.md) to `## [X.Y.Z] - YYYY-MM-DD`, add a new
   empty `## [Unreleased]`, list every fixed vulnerability under its
   `### Security` heading, and merge that change through a pull request.
2. Tag the merge commit and push the tag:

   ```bash
   git tag -s vX.Y.Z -m "veil vX.Y.Z"   # -s signs the tag; see below
   git push origin vX.Y.Z
   ```

3. The tag push runs [`.github/workflows/release.yml`](../.github/workflows/release.yml):
   it reads the version's section of `CHANGELOG.md` (and fails if there is
   none), runs the tests, builds the binaries with GoReleaser
   ([`.goreleaser.yaml`](../.goreleaser.yaml)), writes `SHA256SUMS`, attests
   SLSA v1 build provenance for every asset, signs `SHA256SUMS` with keyless
   cosign, verifies both, and only then publishes the GitHub release with the
   changelog section as its notes.
4. Check the published release with the commands in
   ["Verifying a release"](../README.md#verifying-a-release).

To (re)publish the assets of a tag that already exists, run the workflow by
hand: `gh workflow run release.yml -f tag=vX.Y.Z`. It builds that tag's
sources and never moves the tag.

## Signing keys

Release artifacts are signed keylessly with [Sigstore](https://www.sigstore.dev/):
the signing identity is the release workflow itself
(`https://github.com/FullFran/veil/.github/workflows/release.yml@refs/tags/vX.Y.Z`),
certified by Fulcio and logged in Rekor, so there is no private signing key
to store, rotate or leak. Users verify against that identity, not a key.

Signing the tag itself (`git tag -s`, with an SSH or GPG key registered on
the maintainer's GitHub account) is recommended but not yet required.

## Supported versions

Only the latest release receives fixes ([`SECURITY.md`](../.github/SECURITY.md)).
Upgrading is replacing the binary; any change a host must act on is marked
**Breaking** in the changelog with what to do.
