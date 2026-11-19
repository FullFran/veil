# Roadmap

What veil intends to do next, and what it will not do. Each item links the
issue that tracks it; the [changelog](CHANGELOG.md) records what shipped.
The maintainer reviews this file with every release.

## Next

- **Spanish address detector**: rules for street, number, floor/door, postal
  code and city, so a catalog name inside a street is no longer a name
  ([#50](https://github.com/FullFran/veil/issues/50)).
- **Checksummed identifiers**: CIF, card numbers (Luhn) and NSS
  ([#51](https://github.com/FullFran/veil/issues/51)).
- **Shared memory groundwork**: a threat-model entry for frequency and
  co-occurrence inference on stored pseudonymized text
  ([#52](https://github.com/FullFran/veil/issues/52)), and a design for
  pseudonyms shared across the users of a team
  ([#53](https://github.com/FullFran/veil/issues/53)).
- **Supply chain and assurance**: keep the OpenSSF Scorecard and Best
  Practices answers current
  ([#33](https://github.com/FullFran/veil/issues/33), and
  [docs/openssf-best-practices.md](docs/openssf-best-practices.md)).

## Later

- More detectors for Spanish and EU identifiers (free-text health data
  included), each measured against the evaluation corpus before it ships ([README, Evaluation corpus](README.md#evaluation-corpus)).
- More hosts, through the host-agnostic domain and the ACS server.

## Not planned

- Sending data to any network service: veil works offline by design.
- Being a compliance product: veil enforces exactly what the README lists
  ([What this cannot do](README.md#what-this-cannot-do)).
