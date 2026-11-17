"""Reference NER sidecar for veil's ner detector (FullFran/veil#32).

Run it through `veil model serve`, which verifies the model's files and
sets:

  VEIL_NER_SOCKET     Unix socket path to listen on
  VEIL_NER_MODEL_DIR  directory holding the catalog entry's files
  VEIL_NER_ENTRY      the catalog entry as JSON; its SHA-256 is the entry
                      digest veil expects back in `initialize`

Protocol (version 1): JSON-RPC 2.0, one message per line, one connection
per veil event:

  initialize {protocolVersion: "1"} -> {protocolVersion, model: {id, revision, entryDigest}}
  recognize  {units: [str]}         -> {spans: [[{start, end, label}]]}

Offsets are UTF-8 byte offsets into each unit. The model code follows
research/ner-benchmark/scripts/models.py, which measured these models.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socketserver
import stat
import sys
import tempfile
import threading
import zipfile
from pathlib import Path

PROTOCOL_VERSION = "1"
MAX_LINE = 16 << 20

# GLiNER2's encoder reads a bounded number of tokens and silently drops
# the rest, so long text is split into overlapping windows (characters,
# cut at whitespace). 1000 characters stays well under its limit for
# Spanish text; the overlap keeps a name across a cut whole in one window.
WINDOW_CHARS = 1000
WINDOW_OVERLAP = 200


def byte_offset(text: str, index: int) -> int:
    """UTF-8 byte offset of code point index in text."""
    return len(text[:index].encode("utf-8"))


def windows(text: str, size: int = WINDOW_CHARS, overlap: int = WINDOW_OVERLAP):
    """Yield (start, chunk) windows covering text, each at most size code
    points, consecutive ones overlapping by about overlap, cut at
    whitespace when one is near."""
    if len(text) <= size:
        yield 0, text
        return
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            cut = text.rfind(" ", start + size - overlap, end)
            if cut > start:
                end = cut
        yield start, text[start:end]
        if end >= len(text):
            return
        nxt = end - overlap
        space = text.find(" ", nxt, end)
        start = space + 1 if space >= 0 else max(nxt, start + 1)


def windowed(text: str, find, size: int = WINDOW_CHARS, overlap: int = WINDOW_OVERLAP):
    """Run find on each window of text and return its (start, end, label)
    code point spans shifted into text, without duplicates from overlaps."""
    found = set()
    for offset, chunk in windows(text, size, overlap):
        for start, end, label in find(chunk):
            found.add((offset + start, offset + end, label))
    return sorted(found)


class GLiNER2Runtime:
    def __init__(self, model_dir: Path, labels: list[str], threshold: float):
        from gliner2 import GLiNER2

        self.model = GLiNER2.from_pretrained(str(model_dir))
        if hasattr(self.model, "eval"):
            self.model.eval()
        self.labels = labels
        self.threshold = threshold

    def entities(self, text: str):
        return windowed(text, self._chunk)

    def _chunk(self, chunk: str):
        r = self.model.extract_entities(
            chunk, self.labels, threshold=self.threshold, include_confidence=True, include_spans=True
        )
        for label, items in r.get("entities", {}).items():
            for it in items:
                yield it["start"], it["end"], label


class SpacyRuntime:
    def __init__(self, model_dir: Path, wheel: str):
        import spacy

        self._tmp = tempfile.TemporaryDirectory(prefix="veil-ner-spacy-")
        with zipfile.ZipFile(model_dir / wheel) as z:
            z.extractall(self._tmp.name)
        configs = sorted(Path(self._tmp.name).glob("*/*/config.cfg"))
        if not configs:
            raise RuntimeError(f"{wheel}: no spaCy pipeline inside")
        self.nlp = spacy.load(configs[0].parent)

    def entities(self, text: str):
        return [(e.start_char, e.end_char, e.label_) for e in self.nlp(text).ents]


def load_runtime(entry: dict, model_dir: Path):
    labels = sorted(entry["labels"])
    if entry["runtime"] == "gliner2":
        threshold = entry.get("parameters", {}).get("threshold", 0.5)
        return GLiNER2Runtime(model_dir, labels, threshold)
    if entry["runtime"] == "spacy":
        return SpacyRuntime(model_dir, entry["files"][0]["path"])
    raise RuntimeError(f"unknown runtime {entry['runtime']!r}")


class Handler:
    """Answers protocol requests for one loaded model."""

    def __init__(self, entry_json: str, runtime):
        entry = json.loads(entry_json)
        self.model = {
            "id": entry["id"],
            "revision": entry["source"]["revision"],
            "entryDigest": "sha256:" + hashlib.sha256(entry_json.encode("utf-8")).hexdigest(),
        }
        self.labels = set(entry["labels"])
        self.runtime = runtime
        self.lock = threading.Lock()

    def recognize(self, unit: str):
        with self.lock:
            entities = self.runtime.entities(unit)
        spans = []
        for start, end, label in entities:
            if label in self.labels and 0 <= start < end <= len(unit):
                spans.append({"start": byte_offset(unit, start), "end": byte_offset(unit, end), "label": label})
        return spans

    def answer(self, line: bytes) -> dict:
        try:
            req = json.loads(line)
        except ValueError:
            return error(None, -32700, "parse error")
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "id" not in req:
            return error(None, -32600, "invalid request")
        rid, method, params = req["id"], req.get("method"), req.get("params") or {}
        if method == "initialize":
            if params.get("protocolVersion") != PROTOCOL_VERSION:
                return error(rid, -32602, "unsupported protocol version")
            return result(rid, {"protocolVersion": PROTOCOL_VERSION, "model": self.model})
        if method == "recognize":
            units = params.get("units")
            if not isinstance(units, list) or not all(isinstance(u, str) for u in units):
                return error(rid, -32602, "units must be a list of strings")
            try:
                return result(rid, {"spans": [self.recognize(u) for u in units]})
            except Exception:  # noqa: BLE001 -- any model failure is an error reply, never a crash
                return error(rid, -32603, "recognition failed")
        return error(rid, -32601, "method not found")


def result(rid, value) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": value}


def error(rid, code: int, message: str) -> dict:
    # Messages never echo the request: units can hold personal data.
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def serve_connection(handler: Handler, rfile, wfile):
    while True:
        line = rfile.readline(MAX_LINE + 1)
        if not line or len(line) > MAX_LINE:
            return
        wfile.write(json.dumps(handler.answer(line), ensure_ascii=False).encode("utf-8") + b"\n")
        wfile.flush()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def listen(socket_path: str, handler: Handler) -> Server:
    """Bind socket_path, replacing a stale socket but nothing else, with
    mode 0600."""
    try:
        if stat.S_ISSOCK(os.lstat(socket_path).st_mode):
            os.unlink(socket_path)
    except FileNotFoundError:
        pass

    class Conn(socketserver.StreamRequestHandler):
        def handle(self):
            serve_connection(handler, self.rfile, self.wfile)

    old = os.umask(0o177)
    try:
        return Server(socket_path, Conn)
    finally:
        os.umask(old)


def main() -> int:
    try:
        socket_path = os.environ["VEIL_NER_SOCKET"]
        model_dir = Path(os.environ["VEIL_NER_MODEL_DIR"])
        entry_json = os.environ["VEIL_NER_ENTRY"]
    except KeyError as missing:
        print(f"veil-ner-sidecar: {missing} is not set; run it with `veil model serve`", file=sys.stderr)
        return 2
    runtime = load_runtime(json.loads(entry_json), model_dir)
    handler = Handler(entry_json, runtime)
    server = listen(socket_path, handler)
    # systemd and `kill` stop with SIGTERM: leave through the same cleanup.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print(f"veil-ner-sidecar: serving {handler.model['id']} on {socket_path}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
