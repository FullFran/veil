# veil NER sidecar (reference)

A long-running local process that serves one pinned model of veil's NER
catalog to the `ner` detector, over the Unix socket veil dials on each
event. Protocol and catalog: the "Local NER models" section of the
[veil README](../../README.md#local-ner-models).

Run it only through `veil model serve`, which verifies the model files
against the catalog and passes their location:

```bash
veil model pull gliner2-pii --accept-license Apache-2.0
VEIL_NER_MODEL=gliner2-pii veil model serve \
  uv run --project adapters/ner-sidecar --frozen python adapters/ner-sidecar/veil_ner_sidecar.py
```

For `spacy-es-core-news-lg` add `--extra spacy` to `uv run`.

- **Runtimes.** `gliner2` loads the model directory with
  `GLiNER2.from_pretrained`, asks only for the entry's labels at its
  threshold, and splits long text into overlapping windows; `spacy`
  loads the pinned wheel's pipeline. The model code and the dependency
  versions are those `research/ner-benchmark` measured.
- **Socket.** A stale socket at the path is replaced (any other file is
  not); the new one is created 0600. One connection per veil event;
  inference is serialized. A connection that sends nothing for 10 s is
  closed.
- **Offline.** It sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`
  before any model library loads: the files `veil model serve` verified
  are the only ones used, and nothing is fetched.
- **Privacy.** Nothing is logged about requests, and error replies never
  echo request text.
- **Identity.** `initialize` reports the entry's id and revision, and the
  SHA-256 of `VEIL_NER_ENTRY` as `entryDigest`, which veil checks.

Tests (protocol, offsets, windows, socket, offline) need only the
standard library and a fake model; CI runs them:

```bash
cd adapters/ner-sidecar && python3 -m unittest -v test_sidecar
```

The end-to-end test with the real model is in veil:
`VEIL_NER_E2E=1 go test -run E2E ./cmd/veil/`.
