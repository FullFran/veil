"""Corpus loading with the same markup and unit rules as internal/eval.

A record is {"id", "tags", "text"} or {"id", "tags", "tool", "args"}.
Values are annotated inline as [[LABEL:value]]. Offsets are code points
(Python str indices), which is what internal/eval counts (runes).

Unit names follow internal/eval: "" for prompt text, otherwise the
field path of a string leaf, joined with "." and with "\\" and "."
escaped in keys, array indexes as decimal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# veil's labels plus DIRECCION, which only the research extension set uses.
VEIL_LABELS = ("DNI", "IBAN", "EMAIL", "TEL", "NOMBRE")
LABELS = VEIL_LABELS + ("DIRECCION",)


@dataclass(frozen=True, order=True)
class Span:
    unit: str
    start: int
    end: int
    label: str


@dataclass
class Case:
    id: str
    tags: list[str]
    # Exactly one of text / args is set (plain, annotations stripped).
    text: str | None
    tool: str | None
    args: dict | None
    units: dict[str, str] = field(default_factory=dict)
    gold: list[Span] = field(default_factory=list)


def parse_markup(s: str, unit: str) -> tuple[str, list[Span]]:
    plain: list[str] = []
    spans: list[Span] = []
    pos = 0
    while True:
        i = s.find("[[")
        if i < 0:
            break
        plain.append(s[:i])
        pos += i
        rest = s[i + 2 :]
        j = rest.find("]]")
        if j < 0:
            raise ValueError("unclosed annotation")
        label, sep, value = rest[:j].partition(":")
        if not sep or not value or label not in LABELS:
            raise ValueError(f"malformed annotation {rest[:j]!r}")
        spans.append(Span(unit, pos, pos + len(value), label))
        plain.append(value)
        pos += len(value)
        s = rest[j + 2 :]
    plain.append(s)
    return "".join(plain), spans


def _escape_key(k: str) -> str:
    return k.replace("\\", "\\\\").replace(".", "\\.")


def _join(parent: str, key: str) -> str:
    return key if parent == "" else parent + "." + key


def _strip(v, path: str, spans: list[Span], units: dict[str, str]):
    if isinstance(v, str):
        plain, s = parse_markup(v, path)
        spans.extend(s)
        units[path] = plain
        return plain
    if isinstance(v, dict):
        return {k: _strip(e, _join(path, _escape_key(k)), spans, units) for k, e in v.items()}
    if isinstance(v, list):
        return [_strip(e, _join(path, str(i)), spans, units) for i, e in enumerate(v)]
    return v


def load(corpus_dir: str | Path) -> list[Case]:
    cases = []
    for line in Path(corpus_dir, "corpus.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if ("text" in r) == ("args" in r):
            raise ValueError(f"{r.get('id')}: exactly one of text or args")
        if "text" in r:
            plain, spans = parse_markup(r["text"], "")
            cases.append(Case(r["id"], r.get("tags", []), plain, None, None, {"": plain}, spans))
        else:
            spans: list[Span] = []
            units: dict[str, str] = {}
            args = _strip(r["args"], "", spans, units)
            cases.append(Case(r["id"], r.get("tags", []), None, r.get("tool") or "bash", args, units, spans))
    return cases
