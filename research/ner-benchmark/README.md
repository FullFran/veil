# NER benchmark and MemPrivacy study (FullFran/veil#3)

Research only. Nothing here is part of veil's binary, its Go module or its
test gate. The question is whether an optional local NER detector is worth
adding to veil, and which one, for what the regex and checksum detectors
cannot catch: names outside the catalog, postal addresses, and other
unstructured personal data.

**Short answer.** Yes for names, and only as an opt-in local sidecar.
GLiNER2-PII is the best fit: on the extension set it takes out-of-catalog
names from 2.5% to 92.5% not leaked, with 5 false positives on 25 hard
negatives. The cost is 3 to 4 orders of magnitude more latency than veil
(about 0.1 s p50 and 0.3 s p95 per event, against 39 µs p95 for veil), 1.25 GB on disk,
and 1.8 to 2.9 GB of RAM. Addresses are not solved by any candidate at
usable precision; they need their own detector work first (see the
[improvement list](#prioritized-improvement-list)). OpenAI Privacy Filter
and MemPrivacy are not recommended (see [Recommendation](#recommendation)).

- [Method](#method)
- [Results](#results)
- [Deployment shapes](#deployment-shapes)
- [MemPrivacy](#memprivacy-arxiv-260509530)
- [Recommendation](#recommendation)
- [Prioritized improvement list](#prioritized-improvement-list)
- [Proposal: shared conformance corpus for ports](#proposal-shared-conformance-corpus-for-ports)
- [Reproduce](#reproduce)
- [What could not be verified](#what-could-not-be-verified)

## Method

### Corpora

| set | cases | gold spans | what it is |
|---|---|---|---|
| `es-v1` = `testdata/corpus/es/v1` | 78 | DNI 20, IBAN 12, EMAIL 10, TEL 15, NOMBRE 15 | veil's gate corpus, unchanged |
| `es-ext-v1` = [`data/es-ext-v1`](data/es-ext-v1) | 76 | NOMBRE 45, DIRECCION 18, DNI 1, EMAIL 1, TEL 2 | research extension: 33 out-of-catalog name cases, 17 address cases, 25 hard negatives |

Both are synthetic. The extension set is research data, with its own
[annotation rules](data/es-ext-v1/README.md), and adds the research-only label
`DIRECCION`. The two sets are reported separately and never summed: `es-v1`
has no address gold, so a `DIRECCION` prediction there is neither right nor
wrong and is not scored.

### Metrics

- **Strict span P / R / F1**, the definition in `internal/eval/metrics.go`
  (MEDDOCAN convention: a predicted span is a true positive only when unit,
  start, end and label all equal a gold span; code point offsets; micro
  average sums counts over labels). `scripts/metrics.py` reimplements it, and
  `scripts/score.py` refuses to report anything unless its counts for veil on
  `es-v1` equal the committed `baseline.json` (it prints
  `parity with testdata/corpus/es/v1/baseline.json: OK`).
- **Leak recall** (research addition): a gold span leaks when no predicted
  span of any label overlaps it. Strict F1 answers "are the boundaries and
  label right"; leak answers "did any of it get masked".
- **Character coverage** (research addition): the share of gold characters
  covered by some predicted span. Leak is lenient on long spans: masking
  `Calle Hileras` in `Calle Hileras 4, 2º B, 28013 Madrid` stops the leak
  flag but leaves the number, floor and postal code in clear. Coverage shows
  that.
- **Latency per event**: wall time for all units of one case (the prompt text,
  or every string field of the tool arguments), 5 repeats per case after a
  warm-up, nearest-rank p50 / p95 as in `internal/eval`. **Cold start**:
  process start to first prediction ready (imports, weight loading, one
  warm-up call). **RSS** from `/proc/self/status` after loading, and peak
  from `getrusage`. **Size on disk**: every file of the model directory.
- Machine: AMD Ryzen 5 5500 (6 cores, 12 threads), 15 GiB RAM, Linux, CPU
  only, PyTorch 2.15.0+cpu with 6 intra-op threads, Python 3.12.3.

### Systems and label mapping

veil's spans come from veil's own detectors through
[`_veilspans`](_veilspans/main.go), a Go command that uses the default policy
and the corpus catalog, exactly like `cmd/veil-eval`. Its directory name
starts with `_`, so `go build ./...`, `go vet ./...` and `go test ./...`
ignore it; `go.mod` is untouched.

| system | version / revision | licence | languages (model card) | mapping to veil labels |
|---|---|---|---|---|
| OpenAI Privacy Filter (`opf`) | `openai/privacy-filter`, PyTorch checkpoint `original/`, run with the `opf` package at `f7f00ca` (Viterbi decoding, default operating point) | Apache-2.0 | "Primarily English; selected multilingual robustness evaluation reported" | `private_person`→NOMBRE, `private_address`→DIRECCION, `private_email`→EMAIL, `private_phone`→TEL, `account_number`→IBAN; `private_url`, `private_date`, `secret` not scored |
| GLiNER2-PII (`gliner2-pii`) | `fastino/gliner2-privacy-filter-PII-multi` (205M params per card, 307M in the safetensors header), `gliner2` 2.1.0, threshold 0.5 | Apache-2.0 | en, fr, es, de, it, pt, nl | requested labels `person`→NOMBRE, `address`→DIRECCION, `email`→EMAIL, `phone_number`→TEL, `iban`→IBAN, `national_id_number`→DNI |
| GLiNER2-PII + `street_address` (`gliner2-pii-street`) | same, also requesting `street_address`→DIRECCION | Apache-2.0 | same | **chosen after reading GLiNER2's address misses on `es-ext-v1`, so its numbers are optimistic** |
| Presidio + spaCy sm (`presidio-sm`) | `presidio-analyzer` 2.2.366, spaCy 3.8.18, `es_core_news_sm` 3.8.0 | MIT (Presidio); the spaCy model is GNU GPL 3.0 (its `meta.json`, inherited from UD Spanish AnCora) | es | `PERSON`→NOMBRE, `LOCATION`→DIRECCION (Presidio has no Spanish street-address recognizer), `EMAIL_ADDRESS`→EMAIL, `PHONE_NUMBER`→TEL, `IBAN_CODE`→IBAN, `ES_NIF`/`ES_NIE`→DNI |
| Presidio + spaCy lg (`presidio-lg`) | same with `es_core_news_lg` 3.8.0 | same | es | same |
| BSC MEDDOCAN (`bsc-meddocan`) | `BSC-NLP4BIA/bsc-bio-ehr-es-carmen-meddocan` (RoBERTa base, clinical), transformers 5.23.0, `aggregation_strategy="first"` | CC-BY-4.0 | es | `NOMBRE_PERSONAL_SANITARIO`, `FAMILIARES_SUJETO_ASISTENCIA`→NOMBRE, `CALLE`→DIRECCION, `NUMERO_TELEFONO`→TEL, `ID_SUJETO_ASISTENCIA`, `NUMERO_IDENTIF`→DNI. The checkpoint has no patient-name and no e-mail label |
| MemPrivacy-1.7B-RL (`memprivacy-1.7b`) | `IAAR-Shanghai/MemPrivacy-1.7B-RL` at `c1df3f4`, prompt `src/prompts/extract_privacy.txt` at `e859c42`, greedy, every level PL2-PL4 kept | CC-BY-NC-ND-4.0 | en, zh | `Real Name`, `Third-Party Identifiable Info`→NOMBRE, `Detailed Address`, `Work Address`→DIRECCION, `Phone Number`→TEL, `Email`→EMAIL, `ID Number`→DNI, `Financial Account`→IBAN |

Presidio loaded these recognizers for `es`: CreditCard, Crypto, Date, Email,
EsNie, EsNif, Iban, Ip, MacAddress, MedicalLicense, Phone, Spacy, Url, Uuid.

**veil + model** is the realistic deployment: veil's spans, plus the model's
NOMBRE and DIRECCION spans only. veil's checksummed detectors stay
authoritative for DNI, IBAN, EMAIL and TEL: a model span that overlaps one of
them is dropped. A model span that overlaps a veil NOMBRE span replaces it
when it is longer (veil's own longest-match rule).

### Local-only rule

Weights are downloaded once by `scripts/download.py`, the only step that
uses the network. `scripts/run.py` then sets the Hugging Face libraries
offline and replaces `socket.connect` so that every non-Unix socket fails
before any model code runs. The guard caught two silent fetches during
development, both fixed by caching the file locally: Presidio's `tldextract`
asking for the public suffix list (it falls back to its bundled copy), and
the `opf` tokenizer asking for tiktoken's `o200k_base`. No corpus text was
sent anywhere.

## Results

Full tables: [`results/tables.md`](results/tables.md), generated by
`scripts/score.py` from `results/raw/*.json` (raw spans and timings per
case). Per-case errors are in `results/summary.json`.

### What decides it: names and addresses on `es-ext-v1`

veil + model, NOMBRE and DIRECCION only. Each cell: strict recall / leak
recall / character coverage / false positives (NOMBRE + DIRECCION).

<!-- copied from results/tables.md -->
| system | out-of-catalog names (40 gold spans) | addresses (21 gold spans) | hard negatives (25 cases, no gold) |
|---|---|---|---|
| veil | 0.025 / 0.025 / 0.019 / 0+0 FP | 0.000 / 0.048 / 0.018 / 1+0 FP | 0+0 FP |
| veil + bsc-meddocan | 0.550 / 0.875 / 0.902 / 15+0 FP | 0.143 / 1.000 / 0.723 / 1+19 FP | 1+4 FP |
| veil + gliner2-pii-street | 0.900 / 0.950 / 0.953 / 2+1 FP | 0.571 / 0.905 / 0.711 / 0+7 FP | 3+7 FP |
| veil + gliner2-pii | 0.900 / 0.925 / 0.930 / 2+0 FP | 0.524 / 0.619 / 0.467 / 1+1 FP | 3+2 FP |
| veil + opf | 0.675 / 0.875 / 0.770 / 9+0 FP | 0.381 / 0.905 / 0.715 / 2+16 FP | 1+3 FP |
| veil + presidio-lg | 0.800 / 0.975 / 0.981 / 5+5 FP | 0.143 / 0.905 / 0.623 / 3+26 FP | 3+15 FP |
| veil + presidio-sm | 0.600 / 0.825 / 0.874 / 11+9 FP | 0.095 / 0.905 / 0.605 / 8+22 FP | 7+13 FP |

(The address group's 21 gold spans are 18 `DIRECCION` and 3 `NOMBRE` that
appear in the same cases.)

### Cost on CPU

| model | size on disk (MB) | cold start (s) | RSS loaded (MB) | RSS peak (MB) | p50 es-v1 (ms) | p95 es-v1 (ms) | p50 es-ext (ms) | p95 es-ext (ms) |
|---|---|---|---|---|---|---|---|---|
| veil (`cmd/veil-eval`, full `Evaluate`) | binary only | n/a | n/a | n/a | 0.016 | 0.039 | n/a | n/a |
| presidio-sm | 16.3 | 4.0 | 448 | 449 | 4.2 | 8.0 | 4.4 | 6.8 |
| presidio-lg | 631.2 | 6.1 | 1196 | 1197 | 4.5 | 8.7 | 4.6 | 7.2 |
| bsc-meddocan | 500.0 | 3.9 | 712 | 766 | 39.7 | 67.3 | 39.1 | 71.4 |
| gliner2-pii | 1245.1 | 7.5 | 1764 | 2934 | 106.9 | 271.8 | 118.0 | 193.9 |
| opf | 2799.0 | 11.2 | 3464 | 4165 | 815.3 | 1533.8 | 816.2 | 1329.2 |
| memprivacy-1.7b | 3457.1 | 127.4 | 3789 | 4368 | n/a | n/a | 117,433 (subset) | 142,259 (subset) |

veil's row is `go run ./cmd/veil-eval` on the same machine (`p50 16.0 µs, p95 38.5 µs, max 248.0 µs`, 1560 samples), shown in ms.
`gliner2-pii-street` has the same model and size as `gliner2-pii`; its
latency was measured with one repeat while the MemPrivacy run was using the
CPU, so it is not comparable and is left out here (it is in
`results/tables.md`). MemPrivacy ran with one repeat on a subset (see below).

### `es-v1` (the gate corpus)

On the gate corpus every model, combined with veil, brings NOMBRE recall from
0.867 to 1.000 or 0.933 (the two out-of-catalog names `nombre-006` and
`nombre-007`). The question is what it costs in precision there:

| system | NOMBRE strict P / R / F1 | micro F1 (5 labels) |
|---|---|---|
| veil | 0.929 / 0.867 / 0.897 | 0.959 |
| veil + gliner2-pii | 0.833 / 1.000 / 0.909 | 0.960 |
| veil + gliner2-pii-street | 0.882 / 1.000 / 0.938 | 0.966 |
| veil + presidio-lg | 0.737 / 0.933 / 0.824 | 0.940 |
| veil + presidio-sm | 0.583 / 0.933 / 0.718 | 0.910 |
| veil + bsc-meddocan | 0.733 / 0.733 / 0.733 | 0.925 |
| veil + opf | 0.542 / 0.867 / 0.667 | 0.897 |

DNI, IBAN, EMAIL and TEL stay at veil's numbers in every union by
construction. On their own, no model reaches veil on those labels (best:
Presidio's `ES_NIF` at DNI recall 0.80; OPF finds no DNI at all), which
confirms the split: checksums for structured identifiers, a model only for
names.

### Error analysis

- **GLiNER2-PII** misses whole addresses with the generic `address` label
  (`Calle de Santa Engracia 112, 3º izq., 28003 Madrid`, `Plaza del Pilar 3,
  bajo`, `Urb. Los Pinos, parcela 14, 29600 Marbella`): the leak recall for
  addresses is 0.619. Adding `street_address` takes it to 0.905, but triples
  the false positives on public streets (`Plaza de España`, `Avenida de la
  Constitución` in "hay obras en..."). Its name errors are boundary ones
  (`Domínguez Lara, Patricia` split in two) plus three misses
  (`Valeria Ríos Medina` after `Alta de`, both CSV cells). False positives:
  `Cervantes`, `Lope de Vega`, `director financiero`, and on `es-v1` the
  one-letter tool field `y` and the word `cliente`.
- **Presidio + spaCy** finds almost every name (lg: 0.975 leak, 0.981
  coverage) at 4.5 ms, but its spans carry neighbours (`Nerea?`,
  `JUAN GARCIA HOY`, `Mi hermana`) and it tags many organisations and places
  (`Banco Santander`, `Mercadona`, `Las Palmas`). As an address detector it
  only finds the street name: coverage 0.62. lg is clearly better than sm on
  names (strict 0.80 against 0.60, 3 against 7 false names on negatives).
- **OpenAI Privacy Filter** includes the introducing words in the span
  (`El inquilino Mohamed El Amrani`, `Vive en Avda. de la Constitución 8`,
  `Asiste Gonzalo Peña`), drops second surnames (`Rodrigo Castaño`), misses
  lowercase and all-caps names, and splits addresses into pieces. That fits
  its model card ("Primarily English", "fragmented or shifted span
  boundaries"). On `es-v1` it predicts no DNI.
- **BSC MEDDOCAN** covers addresses fully (leak 1.0) but in fragments (strict
  0.14) and tags many non-address phrases; its label set has no patient name,
  so out-of-catalog names come only from staff and relatives' labels.
- **veil** has one false positive in the set: `María Pérez` inside
  `Calle María Pérez de la Rosa 12` (the same near-miss as `nombre-010`). Every
  model that finds the street there fixes it in the union, because the longer
  address span replaces the catalog match.

### MemPrivacy-1.7B-RL on a subset

Run with one repeat on every third case of `es-ext-v1` (26 cases, chosen by
position, before seeing any output), because one event takes about two
minutes on this CPU. 26 cases is small: one span moves a recall by 7 to 14
points. Same columns as above, all systems scored on the same 26 cases
(also in `results/tables.md`):

<!-- copied from results/tables.md -->
| system | out-of-catalog names (14 gold spans) | addresses (7 gold spans) | hard negatives (9 cases, no gold) |
|---|---|---|---|
| veil | 0.000 / 0.000 / 0.000 / 0+0 FP | 0.000 / 0.000 / 0.000 / 0+0 FP | 0+0 FP |
| veil + bsc-meddocan | 0.500 / 0.929 / 0.973 / 7+0 FP | 0.143 / 1.000 / 0.924 / 0+7 FP | 1+2 FP |
| veil + gliner2-pii-street | 0.929 / 1.000 / 0.989 / 2+0 FP | 0.714 / 0.857 / 0.708 / 0+1 FP | 2+3 FP |
| veil + gliner2-pii | 0.929 / 1.000 / 0.989 / 2+0 FP | 0.714 / 0.714 / 0.597 / 0+0 FP | 2+1 FP |
| veil + memprivacy-1.7b | 0.571 / 0.857 / 0.915 / 3+0 FP | 0.714 / 1.000 / 1.000 / 1+1 FP | 0+0 FP |
| veil + opf | 0.786 / 1.000 / 0.883 / 3+0 FP | 0.429 / 0.857 / 0.725 / 2+2 FP | 1+1 FP |
| veil + presidio-lg | 0.714 / 1.000 / 0.989 / 3+3 FP | 0.286 / 0.857 / 0.626 / 0+6 FP | 3+7 FP |
| veil + presidio-sm | 0.429 / 0.857 / 0.894 / 6+6 FP | 0.143 / 0.857 / 0.637 / 1+5 FP | 6+6 FP |

Despite Spanish not being among its training languages, MemPrivacy is the
only model here with no false positive on the hard negatives and full
address coverage on this subset. Its misses are a first name alone (`Paco`)
and one full name, and its boundary errors are the same as OPF's: it copies
the introducing words into `original_text` (`La Dra. Elena Quiroga`,
`Asiste Gonzalo Peña Vera`, `Vive en Avda. de la Constitución 8, portal 2`)
and joins coordinated names (`Aitor y Itziar Etxeberria`). Because it returns
strings and not offsets, every such error also changes what
`str.replace` would mask. The cost rules it out regardless: p50 117 s,
p95 142 s, max 230 s per event, 127 s cold start, 3.8 GB resident. Its raw
answers are kept in `results/raw/memprivacy-1.7b.json` (`raw_outputs`).

## Deployment shapes

Not implemented here; this is what the numbers imply.

| shape | how | veil binary | fail-closed | fit |
|---|---|---|---|---|
| In-process, ONNX Runtime | hugot with `-tags ORT` and `libonnxruntime.so` | cgo plus a shared library: no longer a static, pure-Go binary | in-process; a crash takes veil down, which denies | fastest; loses the "one static binary" property |
| In-process, pure Go | hugot's GoMLX backend (`NewGoSession`, no cgo) | static, but the binary must load a 0.5 to 2.8 GB model | same | hugot's README: the Go backend "is designed for simpler workloads ... and for smaller models such as all-MiniLM-L6-v2"; its `tokenClassification` pipeline covers BERT/RoBERTa-style heads (BSC). GLiNER2 is not a token-classification head (span scoring against label prompts) and has no hugot pipeline; OPF is a mixture-of-experts graph with a Viterbi decoder. Neither was tried on GoMLX |
| Separate local process over stdio | veil spawns `veil-ner` (any runtime), keeps it alive, sends `{id, units}` lines, reads spans back, with a per-request deadline | unchanged | veil treats a dead, slow or malformed sidecar as a detector failure and denies the event (HCS-0008-R020: when the guard is unavailable or fails, the request must not reach the provider) | keeps veil small and its supply chain unchanged; model and runtime update on their own; cold start (4 to 11 s) paid once per session, not per event |

The sidecar shape is the one that fits veil: the cold start rules out
starting a model per hook call, the RAM rules out loading it into every short
veil process, and a separate process keeps the model's large dependency tree
(PyTorch, or ONNX Runtime) out of veil's release artifacts and their
provenance. A third-party ONNX export of GLiNER2-PII exists on the Hub
(`jugaadsrl/gliner2-privacy-filter-PII-multi-onnx`); it was not evaluated.

## MemPrivacy (arXiv 2605.09530)

Chen et al., *MemPrivacy: Privacy-Preserving Personalized Memory Management
for Edge-Cloud Agents* (MemTensor, HONOR Device, Tongji University),
arXiv:2605.09530 v3, 14 May 2026. Code:
[MemTensor/MemPrivacy](https://github.com/MemTensor/MemPrivacy) (README badge:
CC-BY-NC-ND-4.0; no LICENSE file in the root at `e859c42`). Weights:
`IAAR-Shanghai/MemPrivacy-{1.7B,4B}-{SFT,RL}` on Hugging Face, all
CC-BY-NC-ND-4.0, languages en and zh. The paper also reports a 0.6B model; no
0.6B checkpoint was found.

**What it does.** A small local LLM (Qwen3 0.6B to 4B, SFT then GRPO) reads
each message with a long extraction prompt and returns a JSON list of
`{original_text, privacy_type, privacy_level}`. Levels: PL1 public (not
extracted), PL2 identifiers (name, phone, e-mail, address, account IDs,
third-party contact data), PL3 highly sensitive (ID numbers, financial and
health data, precise location, sensitive attributes), PL4 credentials. Each
extracted string is replaced by a typed placeholder `<Type_N>` (`<Email_1>`,
`<Real_Name_2>`), the mapping is kept in a local SQLite table, and the cloud
answer is restored by looking placeholders up. Detection is model-only: there
are no rules or checksums.

**Evaluation.** Detection P/R/F1 on MemPrivacy-Bench (their data; 26,016
turns from 160 users for training, labels from Gemini-3.1-Pro and GPT-5.2
with human verification on the test split) and on PersonaMem-v2 out of
distribution. Their matching is **not span-strict**: text overlap plus type
similarity by embeddings. Utility is the accuracy of three memory systems
(LangMem, Mem0, Memobase) on the memory QA task with protection against no
protection; the "at most 1.6%" loss is the worst case over PL2-PL4. Baselines
include `***` masking, untyped `<Mask_1>`, 11 general LLMs and OpenAI Privacy
Filter (35.50% F1 on their benchmark per the repo README).

**What applies to veil**

- The design is the same as veil's: local detection, typed and numbered
  placeholders (`[DNI-001]` in veil), local mapping, restoration on the way
  back. Their utility result (typed placeholders lose at most 1.6% against
  0 protection, and beat `***` and untyped masks) is independent evidence
  for veil's choice of typed pseudonyms over blanket redaction.
- Their utility protocol is reusable: run the same memory/QA task with no
  protection, with veil's pseudonyms, and with `***`, and report the
  accuracy delta. veil should measure utility the same way before claiming
  its pseudonyms preserve it.
- The four-level taxonomy is a cleaner way to let a policy choose what to
  mask than per-detector switches, and maps onto veil's categories (DNI, IBAN
  are PL3; NOMBRE, EMAIL, TEL, an address are PL2).

**What does not apply**

- **Licence.** CC-BY-NC-ND-4.0 forbids commercial use and derivatives
  (fine-tuning included). veil is Apache-2.0; it cannot ship, recommend as a
  default, or adapt these weights.
- **Languages.** Trained and evaluated on Chinese and English only.
- **Names.** The prompt only treats the *user's own* full name as a Real Name
  (checked against a `User's Real Name` field); other names fall under
  third-party information. And the repository's default `mask_levels` are
  PL3 and PL4: **names, phones, e-mails and addresses (PL2) stay in clear
  unless the deployer adds PL2.** veil masks all of them by default, which is
  the safer default.
- **Substitution.** `mask_dialogue` replaces each extracted string with
  `str.replace` over the whole message, with no word boundaries and no
  offsets: `Ana` would also be replaced inside `Anabel`. veil replaces spans
  it found at their positions.
- **Consistency across users.** The SQLite table is keyed by the exact
  original text, one store per device: the same person gets the same
  placeholder on one device across sessions, but nothing makes two users
  agree, and `María Pérez` and `MARIA PEREZ` get different numbers. The
  placeholder counter is per type and global, so a server sees how many
  distinct values of each type a user has mentioned and how often each
  repeats. The paper does not discuss what a server can infer from that
  (not found in the text that could be read; see
  [What could not be verified](#what-could-not-be-verified)). veil has the
  same exposure for a shared memory: stable per-team pseudonyms make
  frequency analysis possible, and it should be stated in the threat model.
- **Cost.** Generative extraction with a ~3,000-token prompt: the paper
  reports 0.43 to 2.05 s per message on an A800 GPU; on this CPU it took
  117 s p50 per message (below).

## Recommendation

1. **Add an optional NER detector for names, as a local sidecar process,
   off by default.** Model: **GLiNER2-PII** (Apache-2.0, Spanish in its
   training languages). Expected gain on `es-ext-v1`: out-of-catalog names
   from 0.025 to 0.925 leak recall (strict 0.025 to 0.900), with 3 false
   names and 2 false addresses on the 25 hard negatives; on `es-v1` NOMBRE
   recall from 0.867 to 1.000 while precision drops from 0.929 to 0.833.
   Cost: +107 ms p50 and +272 ms p95 per event on a 6-core desktop CPU (veil
   alone: 39 µs p95), 1.25 GB on disk, 1.8 GB resident (2.9 GB peak), 7.5 s
   cold start once per session. Use it only for NOMBRE; keep veil's
   detectors for every structured label.
2. **Cheap alternative for constrained machines: spaCy `es_core_news_lg`
   PERSON** (through Presidio or directly). 4.5 ms per event and 1.2 GB
   resident, with the highest name leak recall here (0.975), but looser
   boundaries (strict 0.80) and more false names. The spaCy Spanish models
   are GNU GPL 3.0 (`meta.json`), which matters if veil ever bundles or
   redistributes one; a separate, user-installed sidecar keeps that apart.
3. **Do not use OpenAI Privacy Filter** in veil today: on this CPU it takes
   0.8 s p50 and 1.5 s p95 per event, needs 3.5 to 4.2 GB of RAM, is
   English-first, and on Spanish includes introducing words in name spans
   and fragments addresses. Revisit if a Spanish fine-tune appears; its
   fine-tuning tooling is open.
4. **Do not use MemPrivacy's weights** (licence, languages, cost). Reuse its
   utility-evaluation protocol and its level taxonomy instead.
5. **Addresses: not worth a model yet.** The best union only covers 71% of
   address characters, at 7 false positives on 25 negatives. A Spanish
   street-type grammar (see below) is the cheaper next step.

Caveats: the extension set is 76 synthetic cases written for this study,
small enough that one case moves a recall by 2 to 5 points; the
`gliner2-pii-street` variant was chosen on it; nothing here was measured on
real user text.

## Prioritized improvement list

| # | improvement | expected impact (from this study) | cost |
|---|---|---|---|
| 1 | Sidecar NER detector (GLiNER2-PII) for NOMBRE, opt-in, fail-closed, behind a per-request deadline | out-of-catalog names: leak recall 0.025 → 0.925 on `es-ext-v1`; `es-v1` NOMBRE recall 0.867 → 1.000 | 0.1 to 0.3 s per event, 1.25 GB disk, ~2 GB RAM, a new process to supervise |
| 2 | Rule-based Spanish address detector: street-type lexicon (`Calle`, `C/`, `Avda.`, `Plaza`, `Paseo`, `Ronda`, `Travesía`, `Camino`, `Urb.`) + name + number or `s/n`, optional floor/door, optional 5-digit postal code 01000-52999 + city | addresses: 0.048 leak today; every address in `es-ext-v1` has one of these shapes; public streets without a number stay unmasked, which keeps the hard negatives clean | small, pure Go, microseconds; needs its own corpus cases first |
| 3 | Do not match a catalog name inside a street (`Calle María Pérez de la Rosa`) | removes veil's only NOMBRE false positive on both sets | small; falls out of #2 (longest span wins) |
| 4 | Extend the gate corpus with the extension set's shapes (out-of-catalog names, addresses, hard negatives) once veil has a label for addresses | numbers stop being measured only on the shape the regexes were written for | small |
| 5 | Measure utility the MemPrivacy way (QA accuracy with no protection, with veil pseudonyms, with `***`) | evidence that veil's typed pseudonyms cost little utility, on veil's own corpus | medium: needs a QA set and a model run |
| 6 | Threat-model note for shared memory: placeholder frequency and co-occurrence are visible to the server | documents a known inference channel before the shared-memory use case ships | small |
| 7 | Other gaps named in #3 not covered by any detector here: CIF, card numbers (Luhn), NSS (social security number, mod-97 check), free-text health data | CIF, card and NSS have checksums and fit veil's existing pattern; health data needs a model or a lexicon and was not measured | small for the checksummed ones |

## Proposal: shared conformance corpus for ports

A port of veil's rules to another language must produce identical output. The
gate corpus already has most of what is needed:

- **Format**: keep `corpus.jsonl` (`[[LABEL:value]]` inline, `text` or
  `tool` + `args`) and `catalog.json`. Add an `expected.jsonl` with, per case,
  the exact spans (unit, start, end, label, code point offsets) **and** the
  rewritten text with pseudonym tokens for a fresh session, so a port is
  checked on substitution, not only on detection.
- **Versioning**: directories are versioned (`es/v1`, `es/v2`); a version is
  immutable once released, and its `SHA256SUMS` is published with veil's
  release assets so a port can pin it.
- **Conformance rule**: a port conforms to `es/vN` when its spans and
  rewritten text equal `expected.jsonl` byte for byte. Gold annotations and
  expected output are kept apart because they differ on purpose (veil's
  known misses are in `expected`, not in gold).
- **This harness** is a second implementation of the metric already
  (`scripts/metrics.py` against `internal/eval`), and `score.py`'s parity
  check is the shape a port's CI would run.

## Reproduce

Python 3.12 and [uv](https://docs.astral.sh/uv/); the environment is pinned
by `pyproject.toml` and `uv.lock` (CPU-only PyTorch index). The `.venv` is
gitignored; weights live in `~/.cache/huggingface` and
`~/.cache/veil-ner-bench`, outside the repository.

```sh
cd research/ner-benchmark
uv sync --frozen
.venv/bin/python -I scripts/download.py          # the only step that uses the network (~7 GB)
for m in presidio-sm presidio-lg bsc-meddocan gliner2-pii opf; do
  .venv/bin/python -I scripts/run.py --model $m --repeats 5
done
.venv/bin/python -I scripts/run.py --model gliner2-pii-street --repeats 1
.venv/bin/python -I scripts/run.py --model memprivacy-1.7b --repeats 1 --corpus es-ext-v1 --every 3
.venv/bin/python -I scripts/score.py             # needs Go; prints the parity check, writes results/
cd ../.. && go run ./cmd/veil-eval               # veil's own latency on es-v1
```

Run the models one at a time: OPF and MemPrivacy each need 3.5 to 4.2 GB.

## What could not be verified

- MemPrivacy paper sections 4.4 to 6 and the appendices were read only
  through a summary (the HTML could not be fetched whole): the SFT/GRPO
  details, the per-table latency numbers and whether a limitations section
  exists are marked as such above. Whether the paper discusses
  frequency inference from placeholders: not found.
- MemPrivacy code licence: only the README badge (no LICENSE file at
  `e859c42`).
- hugot's GoMLX backend on GLiNER2, OPF or BSC graphs: not tried. Statements
  about it come from hugot's README (v0.8.6).
- OPF's ONNX exports (`onnx/model_q4.onnx` and others) were not measured; an
  int4/int8 ONNX run may be much faster than the PyTorch bf16 path measured
  here, which this CPU (no native bf16) runs slowly.
- GLiNER2-PII's paper (arXiv 2605.09973) was not read; its precision figures
  above come from the model card.
