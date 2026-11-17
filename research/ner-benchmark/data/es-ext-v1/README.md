# es-ext-v1: research extension set (synthetic, not a veil gate)

**Research data.** Every name, address and identifier here is invented for
this benchmark. The set is not part of veil's evaluation gate
(`testdata/corpus/es/v1`), is not read by `go test` or `cmd/veil-eval`, and
uses one label veil does not have (`DIRECCION`), which `internal/eval`
rejects on purpose.

It exists because the gate corpus has 15 names and no addresses, so a model
compared only there would be judged on the shape the regex detectors were
written for. 76 cases:

| group (tag) | cases | what it tests |
|---|---|---|
| `out-of-catalog` | 33 | names veil's catalog does not hold: full names, first names alone, particles (`de la`, `del`), compound and Catalan `i` surnames, Basque, Galician, foreign, all-caps, lowercase, titles (`Dra.`, `D.`), surname-first lists, CSV, code, tool arguments |
| `catalog` | 2 (`cat-001` is also `out-of-catalog`) | controls: catalog names next to new ones |
| `address` | 17 | postal addresses: full, abbreviated (`C/`, `Avda.`, `Urb.`), `s/n`, number-first, lowercase, multiline, inside tool arguments, and a street named after a catalog name |
| `hard-negative` | 25 | no personal data: common nouns that are also names (`rosa`, `pilar`, `victoria`, `rocío`), public streets in non-personal sentences (`la calle Alcalá estará cortada`), organisations, places, historical figures, products, code |

Format: the same as `testdata/corpus/es/v1` (`[[LABEL:value]]` inline, one
JSON record per line, `text` or `tool` + `args`). `catalog.json` is a copy of
the gate corpus catalog, so "out of catalog" means the same thing in both.

Annotation rules:

- `NOMBRE`: the name as written, without titles (`Dra.`, `D.`) and without
  the introducing words. A first name alone is a name. In a
  `Surname Surname, Name` list the whole run is one span.
- `DIRECCION`: one span from the street type to the last element of the same
  comma-separated address: number, floor/door, postal code and city when
  they follow directly. A city mentioned separately ("..., Valladolid.") is
  not part of it. This merges MEDDOCAN's `CALLE` and `TERRITORIO` on
  purpose: veil would replace the whole address with one pseudonym.
- A public street in a sentence about the street itself (traffic, works,
  parades) is not an address of a person and is not annotated.
