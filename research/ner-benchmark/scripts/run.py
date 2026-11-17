"""Run one model over both corpora on CPU and write raw predictions plus
latency, cold start and RAM peak to results/raw/<model>.json.

Usage: python -I scripts/run.py --model opf [--repeats 5]

Local only: before any model code runs, a guard makes every outbound
socket connection raise, and the Hugging Face libraries are put in
offline mode. Weights must already be in the local cache (download.py).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import socket
import sys
import time
from pathlib import Path

START = time.perf_counter()

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"


def _deny(*_a, **_k):
    raise OSError("network disabled by veil-ner-benchmark netguard (local-only rule)")


_orig_connect = socket.socket.connect


def _guarded_connect(self, address):
    if self.family == socket.AF_UNIX:
        return _orig_connect(self, address)
    _deny()


socket.socket.connect = _guarded_connect
socket.create_connection = _deny

import corpus as corpus_mod  # noqa: E402
import metrics  # noqa: E402
from models import ADAPTERS  # noqa: E402

CORPORA = {
    "es-v1": ROOT.parent.parent / "testdata" / "corpus" / "es" / "v1",
    "es-ext-v1": ROOT / "data" / "es-ext-v1",
}


def rss_mb() -> float:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return 0.0


def peak_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def dir_size_mb(p: Path) -> float:
    # Every file of the weights directory (symlinks into the HF blob store
    # are followed), so tokenizers and configs count too.
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1e6


def cpu_model() -> str:
    for line in open("/proc/cpuinfo"):
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=sorted(ADAPTERS))
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--corpus", choices=sorted(CORPORA), help="run one corpus only")
    ap.add_argument("--every", type=int, default=1, help="keep every N-th case (deterministic subset for slow models)")
    args = ap.parse_args()

    import torch

    adapter = ADAPTERS[args.model]()
    rss_before = rss_mb()
    t0 = time.perf_counter()
    adapter.load()
    load_s = time.perf_counter() - t0
    # Cold start: process start to first real prediction ready.
    cold_s = time.perf_counter() - START
    rss_loaded = rss_mb()

    out = {
        "model": adapter.name,
        "model_id": adapter.model_id,
        "label_map": adapter.LABEL_MAP,
        "recognizers": getattr(adapter, "recognizers", None),
        "env": {
            "cpu": cpu_model(),
            "logical_cpus": os.cpu_count(),
            "torch_threads": torch.get_num_threads(),
            "torch": torch.__version__,
            "python": platform.python_version(),
        },
        "size_on_disk_mb": round(dir_size_mb(adapter.weights_dir()), 1),
        "load_s": round(load_s, 3),
        "cold_start_s": round(cold_s, 3),
        "rss_before_load_mb": round(rss_before, 1),
        "rss_loaded_mb": round(rss_loaded, 1),
        "repeats": args.repeats,
        "corpora": {},
    }
    out["subset"] = {"corpus": args.corpus, "every": args.every}
    for cname, cdir in CORPORA.items():
        if args.corpus and cname != args.corpus:
            continue
        cases = corpus_mod.load(cdir)[:: args.every]
        samples = []
        preds = {}
        with torch.inference_mode():
            for cs in cases:
                spans = None
                for _ in range(args.repeats):
                    t = time.perf_counter()
                    cur = []
                    for unit, text in cs.units.items():
                        for start, end, label, score in adapter.predict(text):
                            cur.append({"unit": unit, "start": start, "end": end, "raw": label, "score": score})
                    samples.append((time.perf_counter() - t) * 1e6)
                    spans = cur
                preds[cs.id] = spans
        out["corpora"][cname] = {
            "cases": len(cases),
            "predictions": preds,
            "latency": {
                "samples": len(samples),
                "p50Micros": round(metrics.percentile(samples, 50), 1),
                "p95Micros": round(metrics.percentile(samples, 95), 1),
                "maxMicros": round(metrics.percentile(samples, 100), 1),
            },
        }
    out["rss_peak_mb"] = round(peak_mb(), 1)
    if hasattr(adapter, "raw_outputs"):
        out["raw_outputs"] = adapter.raw_outputs
    dest = ROOT / "results" / "raw" / f"{adapter.name}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=1, default=float) + "\n", encoding="utf-8")
    lat = {k: v["latency"] for k, v in out["corpora"].items()}
    print(json.dumps({k: out[k] for k in ("model", "size_on_disk_mb", "cold_start_s", "rss_loaded_mb", "rss_peak_mb")} | {"latency": lat}))


if __name__ == "__main__":
    main()
