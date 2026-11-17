# Roadmap

What veil intends to do next, and what it will not do. Each item links the
issue that tracks it; the [changelog](CHANGELOG.md) records what shipped.
The maintainer reviews this file with every release.

## Next

- **Release 0.2.0** with the Unreleased changes in the changelog (store
  format with injective file names, problem-details failures, declarative
  policy, decision evidence, ACS server, signed and attested assets).
- **Optional local NER detector** for names that are not in a catalog: a
  pluggable detector behind a port, with a model the user selects and pins,
  off by default ([#32](https://github.com/FullFran/veil/issues/32), research
  in [#3](https://github.com/FullFran/veil/issues/3)).
- **Supply chain and assurance**: keep the OpenSSF Scorecard and Best
  Practices answers current
  ([#33](https://github.com/FullFran/veil/issues/33), and
  [docs/openssf-best-practices.md](docs/openssf-best-practices.md)).

## Later

- More detectors for Spanish and EU identifiers, each measured against the
  evaluation corpus before it ships ([README, Evaluation corpus](README.md#evaluation-corpus)).
- More hosts, through the host-agnostic domain and the ACS server.

## Not planned

- Sending data to any network service: veil works offline by design.
- Being a compliance product: veil enforces exactly what the README lists
  ([What this cannot do](README.md#what-this-cannot-do)).
