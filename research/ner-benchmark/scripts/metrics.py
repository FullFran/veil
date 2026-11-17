"""Metrics, matching internal/eval/metrics.go.

strict: a predicted span is a true positive only when an identical gold
span (unit, start, end, label) exists (MEDDOCAN strict span convention).
P = TP/(TP+FP) or 1 when nothing was predicted; R = TP/(TP+FN) or 1 when
nothing was gold; F1 = 2TP/(2TP+FP+FN) or 1 when both are empty. Micro
sums the counts over labels.

leak (research addition, not in internal/eval): a gold span "leaks" when
no predicted span of any label overlaps it, so its characters would reach
the model provider in clear. leak recall = 1 - leaked/gold. It ignores
boundaries and labels on purpose: it is the privacy question, while strict
is the comparability question.
"""

from __future__ import annotations

from collections import defaultdict

from corpus import Span


def strict_counts(gold: list[Span], pred: list[Span], counts: dict) -> None:
    gs, ps = set(gold), set(pred)
    for p in ps:
        c = counts[p.label]
        c["tp" if p in gs else "fp"] += 1
    for g in gs:
        if g not in ps:
            counts[g.label]["fn"] += 1


def new_counts(labels) -> dict:
    d = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for label in labels:
        d[label]
    return d


def leak_counts(gold: list[Span], pred: list[Span], counts: dict) -> None:
    for g in set(gold):
        hit = any(p.unit == g.unit and p.start < g.end and g.start < p.end for p in pred)
        c = counts[g.label]
        c["gold"] += 1
        if not hit:
            c["leaked"] += 1


def coverage_counts(gold: list[Span], pred: list[Span], counts: dict) -> None:
    """Character coverage: how many characters of each gold span
    some predicted span (any label) covers. Stricter than leak for long
    spans: masking "Calle Hileras" in "Calle Hileras 4, 2º B, 28013 Madrid"
    stops the leak flag but leaves most of the address in clear."""
    for g in set(gold):
        covered = [False] * (g.end - g.start)
        for p in pred:
            if p.unit == g.unit:
                for i in range(max(p.start, g.start), min(p.end, g.end)):
                    covered[i - g.start] = True
        c = counts[g.label]
        c["chars"] += g.end - g.start
        c["covered"] += sum(covered)


def new_leak(labels) -> dict:
    d = defaultdict(lambda: {"gold": 0, "leaked": 0, "chars": 0, "covered": 0})
    for label in labels:
        d[label]
    return d


def precision(c) -> float:
    return 1.0 if c["tp"] + c["fp"] == 0 else c["tp"] / (c["tp"] + c["fp"])


def recall(c) -> float:
    return 1.0 if c["tp"] + c["fn"] == 0 else c["tp"] / (c["tp"] + c["fn"])


def f1(c) -> float:
    d = 2 * c["tp"] + c["fp"] + c["fn"]
    return 1.0 if d == 0 else 2 * c["tp"] / d


def micro(counts: dict, labels) -> dict:
    m = {"tp": 0, "fp": 0, "fn": 0}
    for label in labels:
        for k in m:
            m[k] += counts[label][k]
    return m


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile, as internal/eval.percentile."""
    if not values:
        return 0.0
    s = sorted(values)
    rank = int(p / 100 * len(s) + 0.999999999) - 1
    return s[max(0, min(rank, len(s) - 1))]
