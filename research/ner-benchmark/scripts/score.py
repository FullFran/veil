"""Score veil, every model in results/raw/, and "veil + model" on both
corpora. Writes results/summary.json and results/tables.md.

Usage: python -I scripts/score.py  (needs Go: runs ./_veilspans)

veil's spans come from veil's own detectors through _veilspans (same
detector set as cmd/veil-eval with the default policy and the corpus
catalog). The script first checks that its numbers on es-v1 equal the
committed baseline (testdata/corpus/es/v1/baseline.json), so the Python
metrics are proven identical to internal/eval before anything else is
reported.

Union ("veil + model"): veil's spans, plus the model's NOMBRE and
DIRECCION spans only (veil's checksummed detectors stay authoritative for
DNI, IBAN, EMAIL and TEL). A model span that overlaps a veil DNI, IBAN,
EMAIL or TEL span is dropped; one that overlaps a veil NOMBRE span
replaces it when it is longer (the longest-match rule veil's own
substitution uses).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT.parent.parent
sys.path.insert(0, str(HERE))

import corpus as corpus_mod  # noqa: E402
import metrics as M  # noqa: E402
from corpus import LABELS, VEIL_LABELS, Span  # noqa: E402

CORPORA = {
    "es-v1": REPO / "testdata" / "corpus" / "es" / "v1",
    "es-ext-v1": ROOT / "data" / "es-ext-v1",
}
# Labels scored per corpus: es-v1 has no DIRECCION gold, so a DIRECCION
# prediction there is neither right nor wrong; it is counted apart.
SCORED = {"es-v1": VEIL_LABELS, "es-ext-v1": LABELS}
MODEL_ONLY_LABELS = ("NOMBRE", "DIRECCION")
STRUCTURED = ("DNI", "IBAN", "EMAIL", "TEL")


def veil_spans(cases, catalog: Path) -> dict[str, list[Span]]:
    lines = []
    for cs in cases:
        rec = {"id": cs.id, "text": cs.text} if cs.text is not None else {"id": cs.id, "tool": cs.tool, "args": cs.args}
        lines.append(json.dumps(rec, ensure_ascii=False))
    out = subprocess.run(
        ["go", "run", "./research/ner-benchmark/_veilspans", "-catalog", str(catalog)],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        cwd=REPO,
        check=True,
    ).stdout
    res = {}
    for line in out.splitlines():
        r = json.loads(line)
        res[r["id"]] = [Span(s["unit"], s["start"], s["end"], s["label"]) for s in r["spans"]]
    return res


def overlaps(a: Span, b: Span) -> bool:
    return a.unit == b.unit and a.start < b.end and b.start < a.end


def union(veil: list[Span], model: list[Span]) -> list[Span]:
    out = list(veil)
    for m in (s for s in model if s.label in MODEL_ONLY_LABELS):
        hits = [v for v in out if overlaps(v, m)]
        if any(h.label in STRUCTURED for h in hits):
            continue
        if any((h.end - h.start) >= (m.end - m.start) for h in hits):
            continue
        out = [v for v in out if v not in hits] + [m]
    return out


def score(cases, preds: dict[str, list[Span]], labels) -> dict:
    strict = M.new_counts(labels)
    leak = M.new_leak(labels)
    unscored = 0
    for cs in cases:
        p = [s for s in preds.get(cs.id, []) if s.label in labels]
        unscored += len(preds.get(cs.id, [])) - len(p)
        M.strict_counts(cs.gold, p, strict)
        M.leak_counts(cs.gold, preds.get(cs.id, []), leak)
        M.coverage_counts(cs.gold, preds.get(cs.id, []), leak)
    res = {"labels": {}, "unscored_predictions": unscored}
    for label in labels:
        c = strict[label]
        lk = leak[label]
        res["labels"][label] = {
            **c,
            "P": round(M.precision(c), 4),
            "R": round(M.recall(c), 4),
            "F1": round(M.f1(c), 4),
            "gold": lk["gold"],
            "leaked": lk["leaked"],
            "leakR": round(1 - lk["leaked"] / lk["gold"], 4) if lk["gold"] else 1.0,
            "charCov": round(lk["covered"] / lk["chars"], 4) if lk["chars"] else 1.0,
        }
    m = M.micro(strict, labels)
    res["micro"] = {**m, "P": round(M.precision(m), 4), "R": round(M.recall(m), 4), "F1": round(M.f1(m), 4)}
    return res


GROUPS = {
    "out-of-catalog names": lambda cs: "out-of-catalog" in cs.tags,
    "addresses": lambda cs: "address" in cs.tags,
    "hard negatives": lambda cs: "hard-negative" in cs.tags,
}


def by_group(cases, preds) -> dict:
    """NOMBRE and DIRECCION only, per case group of the extension set:
    strict recall, leak recall, character coverage, and false positives
    split by label."""
    res = {}
    for g, sel in GROUPS.items():
        sub = [cs for cs in cases if sel(cs)]
        lab = score(sub, preds, ("NOMBRE", "DIRECCION"))["labels"]
        n, d = lab["NOMBRE"], lab["DIRECCION"]
        gold = n["gold"] + d["gold"]
        chars = sum(cs_chars(sub, l) for l in ("NOMBRE", "DIRECCION"))
        cov = n["charCov"] * cs_chars(sub, "NOMBRE") + d["charCov"] * cs_chars(sub, "DIRECCION")
        res[g] = {
            "cases": len(sub),
            "gold": gold,
            "strictR": round((n["tp"] + d["tp"]) / gold, 4) if gold else None,
            "leakR": round(1 - (n["leaked"] + d["leaked"]) / gold, 4) if gold else None,
            "charCov": round(cov / chars, 4) if chars else None,
            "fpNOMBRE": n["fp"],
            "fpDIRECCION": d["fp"],
        }
    return res


def cs_chars(cases, label) -> int:
    return sum(s.end - s.start for cs in cases for s in cs.gold if s.label == label)


def mapped(raw: dict, label_map: dict) -> dict[str, list[Span]]:
    out = {}
    for cid, spans in raw.items():
        out[cid] = sorted(
            {Span(s["unit"], s["start"], s["end"], label_map[s["raw"]]) for s in spans if s["raw"] in label_map}
        )
    return out


def errors(cases, preds, labels) -> dict:
    """Strict misses and false positives per case, for the README's error analysis."""
    res = {}
    for cs in cases:
        units = cs.units
        g = {s for s in cs.gold if s.label in labels}
        p = {s for s in preds.get(cs.id, []) if s.label in labels}
        fn = [f"{s.label}:{units[s.unit][s.start:s.end]}" for s in sorted(g - p)]
        fp = [f"{s.label}:{units[s.unit][s.start:s.end]}" for s in sorted(p - g)]
        if fn or fp:
            res[cs.id] = {"fn": fn, "fp": fp}
    return res


def main() -> None:
    corpora = {k: corpus_mod.load(v) for k, v in CORPORA.items()}
    veil = {k: veil_spans(cases, CORPORA[k] / "catalog.json") for k, cases in corpora.items()}

    # Parity gate with internal/eval.
    base = json.loads((CORPORA["es-v1"] / "baseline.json").read_text())["report"]["labels"]
    got = score(corpora["es-v1"], veil["es-v1"], VEIL_LABELS)["labels"]
    for label, c in base.items():
        g = got[label]
        if (g["tp"], g["fp"], g["fn"]) != (c["tp"], c["fp"], c["fn"]):
            raise SystemExit(f"parity check failed for {label}: python {g} vs baseline {c}")
    print("parity with testdata/corpus/es/v1/baseline.json: OK")

    summary = {"systems": {}}
    summary["systems"]["veil"] = {
        cname: {"scores": score(cases, veil[cname], SCORED[cname]), "errors": errors(cases, veil[cname], SCORED[cname])}
        for cname, cases in corpora.items()
    }
    summary["systems"]["veil"]["es-ext-v1"]["groups"] = by_group(corpora["es-ext-v1"], veil["es-ext-v1"])
    subsets = {}
    raw_preds = {}
    for raw_path in sorted((ROOT / "results" / "raw").glob("*.json")):
        raw = json.loads(raw_path.read_text())
        name = raw["model"]
        raw_preds[name] = mapped(raw["corpora"].get("es-ext-v1", {}).get("predictions", {}), raw["label_map"])
        entry = {k: raw[k] for k in raw if k != "corpora"}
        for cname, all_cases in corpora.items():
            if cname not in raw["corpora"]:
                continue
            ids = set(raw["corpora"][cname]["predictions"])
            cases = [cs for cs in all_cases if cs.id in ids]
            preds = mapped(raw["corpora"][cname]["predictions"], raw["label_map"])
            u = {cid: union(veil[cname].get(cid, []), preds.get(cid, [])) for cid in ids}
            entry[cname] = {
                "cases": len(cases),
                "latency": raw["corpora"][cname]["latency"],
                "model": {"scores": score(cases, preds, SCORED[cname]), "errors": errors(cases, preds, SCORED[cname])},
                "union": {"scores": score(cases, u, SCORED[cname]), "errors": errors(cases, u, SCORED[cname])},
            }
            if cname == "es-ext-v1":
                entry[cname]["model"]["groups"] = by_group(cases, preds)
                entry[cname]["union"]["groups"] = by_group(cases, u)
        subset = raw.get("subset") or {}
        if subset.get("every", 1) > 1 or subset.get("corpus"):
            entry["subset_ids"] = sorted(raw["corpora"]["es-ext-v1"]["predictions"])
            subsets[name] = entry["subset_ids"]
        summary["systems"][name] = entry
    # Slow models run on a subset: compare every system on the same cases.
    ext = corpora["es-ext-v1"]
    for name, ids in subsets.items():
        sub = [cs for cs in ext if cs.id in set(ids)]
        rows = {"veil": by_group(sub, veil["es-ext-v1"])}
        for m, preds in raw_preds.items():
            if all(i in preds for i in ids):
                rows[f"veil + {m}"] = by_group(
                    sub, {cid: union(veil["es-ext-v1"].get(cid, []), preds.get(cid, [])) for cid in ids}
                )
        summary.setdefault("subset_comparisons", {})[name] = {"cases": len(sub), "ids": ids, "groups": rows}
    (ROOT / "results" / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    (ROOT / "results" / "tables.md").write_text(tables(summary))
    print(tables(summary))


def fmt(x) -> str:
    return f"{x:.3f}"


def tables(summary) -> str:
    out = ["<!-- generated by scripts/score.py; do not edit -->", ""]
    systems = summary["systems"]
    models = [k for k in systems if k != "veil"]
    for cname in CORPORA:
        labels = SCORED[cname]
        out.append(f"### {cname}: strict span P / R / F1 per label (micro over {', '.join(labels)})")
        out.append("")
        out.append("| system | " + " | ".join(labels) + " | micro F1 |")
        out.append("|---" * (len(labels) + 2) + "|")
        rows = [("veil", systems["veil"][cname]["scores"])]
        for m in models:
            if cname not in systems[m] or "subset_ids" in systems[m]:
                continue
            rows.append((m, systems[m][cname]["model"]["scores"]))
            rows.append((f"veil + {m}", systems[m][cname]["union"]["scores"]))
        for name, s in rows:
            cells = [f"{fmt(s['labels'][l]['P'])} / {fmt(s['labels'][l]['R'])} / {fmt(s['labels'][l]['F1'])}" for l in labels]
            out.append(f"| {name} | " + " | ".join(cells) + f" | {fmt(s['micro']['F1'])} |")
        out.append("")
        out.append(f"### {cname}: leak recall (gold spans overlapped by any prediction; leaked/gold) and character coverage")
        out.append("")
        out.append("| system | " + " | ".join(labels) + " |")
        out.append("|---" * (len(labels) + 1) + "|")
        for name, s in rows:
            cells = [
                f"{fmt(s['labels'][l]['leakR'])} ({s['labels'][l]['leaked']}/{s['labels'][l]['gold']}), cov {fmt(s['labels'][l]['charCov'])}"
                for l in labels
            ]
            out.append(f"| {name} | " + " | ".join(cells) + " |")
        out.append("")
    out.append("### es-ext-v1 by case group: NOMBRE + DIRECCION (strict recall / leak recall / character coverage / false positives NOMBRE+DIRECCION)")
    out.append("")
    vg = systems["veil"]["es-ext-v1"]["groups"]
    heads = [f"{g} ({vg[g]['gold']} gold spans)" if vg[g]["gold"] else f"{g} ({vg[g]['cases']} cases, no gold)" for g in GROUPS]
    out.append("| system | " + " | ".join(heads) + " |")
    out.append("|---" * (len(GROUPS) + 1) + "|")
    grows = [("veil", systems["veil"]["es-ext-v1"]["groups"])]
    for m in models:
        if "subset_ids" in systems[m]:
            continue
        grows.append((f"veil + {m}", systems[m]["es-ext-v1"]["union"]["groups"]))
    out.extend(group_rows(grows))
    for name, comp in summary.get("subset_comparisons", {}).items():
        out.append(f"### es-ext-v1 subset used for {name} ({comp['cases']} cases, every 3rd): same columns, all systems on the same cases")
        out.append("")
        g0 = comp["groups"]["veil"]
        heads = [f"{g} ({g0[g]['gold']} gold spans)" if g0[g]["gold"] else f"{g} ({g0[g]['cases']} cases, no gold)" for g in GROUPS]
        out.append("| system | " + " | ".join(heads) + " |")
        out.append("|---" * (len(GROUPS) + 1) + "|")
        out.extend(group_rows(list(comp["groups"].items())))
    out.append("### Cost on CPU (per event = all units of one corpus case)")
    out.append("")
    out.append("| model | size on disk (MB) | cold start (s) | RSS loaded (MB) | RSS peak (MB) | p50 es-v1 (ms) | p95 es-v1 (ms) | p50 es-ext (ms) | p95 es-ext (ms) |")
    out.append("|---|---|---|---|---|---|---|---|---|")
    for m in models:
        s = systems[m]
        a, b = s.get("es-v1", {}).get("latency"), s["es-ext-v1"]["latency"]
        av = f"{a['p50Micros']/1000:.1f} | {a['p95Micros']/1000:.1f}" if a else "n/a | n/a"
        out.append(
            f"| {m} | {s['size_on_disk_mb']} | {s['cold_start_s']} | {s['rss_loaded_mb']} | {s['rss_peak_mb']} | "
            f"{av} | {b['p50Micros']/1000:.1f} | {b['p95Micros']/1000:.1f} |"
        )
    out.append("")
    return "\n".join(out) + "\n"


def group_rows(grows) -> list[str]:
    out = []
    for name, gs in grows:
        cells = []
        for g in GROUPS:
            x = gs[g]
            fp = f"{x['fpNOMBRE']}+{x['fpDIRECCION']} FP"
            if x["gold"]:
                cells.append(f"{fmt(x['strictR'])} / {fmt(x['leakR'])} / {fmt(x['charCov'])} / {fp}")
            else:
                cells.append(fp)
        out.append(f"| {name} | " + " | ".join(cells) + " |")
    out.append("")
    return out


if __name__ == "__main__":
    main()
