"""Protocol tests for the reference sidecar, with a fake model: they need
only the standard library (python3 -m unittest -v)."""

import hashlib
import json
import os
import socket
import tempfile
import threading
import unittest

import veil_ner_sidecar as sc

ENTRY = json.dumps(
    {"id": "gliner2-pii", "runtime": "gliner2", "source": {"repo": "r", "revision": "abc"}, "labels": {"person": "NOMBRE"}},
    separators=(",", ":"),
)


class FakeRuntime:
    """Finds every word in self.names as a person, and "Madrid" as a location."""

    def __init__(self, names=("Íñigo Pérez",), fail=False):
        self.names, self.fail = names, fail

    def entities(self, text):
        if self.fail:
            raise RuntimeError("boom " + text)
        out = []
        for name in self.names:
            i = text.find(name)
            if i >= 0:
                out.append((i, i + len(name), "person"))
        i = text.find("Madrid")
        if i >= 0:
            out.append((i, i + 6, "location"))
        return out


def call(handler, method, params, rid=1):
    return handler.answer(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode())


class ProtocolTest(unittest.TestCase):
    def test_initialize_reports_the_model_and_entry_digest(self):
        r = call(sc.Handler(ENTRY, FakeRuntime()), "initialize", {"protocolVersion": "1"})
        self.assertEqual(r["result"]["protocolVersion"], "1")
        self.assertEqual(
            r["result"]["model"],
            {"id": "gliner2-pii", "revision": "abc", "entryDigest": "sha256:" + hashlib.sha256(ENTRY.encode()).hexdigest()},
        )

    def test_initialize_other_version_is_an_error(self):
        r = call(sc.Handler(ENTRY, FakeRuntime()), "initialize", {"protocolVersion": "2"})
        self.assertEqual(r["error"]["code"], -32602)

    def test_recognize_returns_utf8_byte_offsets_for_requested_labels(self):
        unit = "Habla con Íñigo Pérez en Madrid"
        r = call(sc.Handler(ENTRY, FakeRuntime()), "recognize", {"units": [unit, "nada"]}, rid=2)
        self.assertEqual(r["id"], 2)
        [spans, none] = r["result"]["spans"]
        self.assertEqual(none, [])
        self.assertEqual(len(spans), 1)
        b = unit.encode()
        self.assertEqual(b[spans[0]["start"] : spans[0]["end"]].decode(), "Íñigo Pérez")
        self.assertEqual(spans[0]["label"], "person")

    def test_bad_requests_are_errors(self):
        h = sc.Handler(ENTRY, FakeRuntime())
        self.assertEqual(h.answer(b"{not json")["error"]["code"], -32700)
        self.assertEqual(h.answer(b'{"jsonrpc":"1.0","id":1}')["error"]["code"], -32600)
        self.assertEqual(call(h, "recognize", {"units": "x"})["error"]["code"], -32602)
        self.assertEqual(call(h, "shutdown", {})["error"]["code"], -32601)

    def test_model_failure_is_an_error_that_does_not_echo_the_text(self):
        r = call(sc.Handler(ENTRY, FakeRuntime(fail=True)), "recognize", {"units": ["Íñigo Pérez"]})
        self.assertEqual(r["error"]["code"], -32603)
        self.assertNotIn("Íñigo", json.dumps(r, ensure_ascii=False))


class WindowsTest(unittest.TestCase):
    def test_short_text_is_one_window(self):
        self.assertEqual(list(sc.windows("hola")), [(0, "hola")])

    def test_long_text_is_covered_by_bounded_overlapping_windows(self):
        text = " ".join(f"palabra{i}" for i in range(2000))
        ws = list(sc.windows(text, size=300, overlap=60))
        covered = set()
        for start, chunk in ws:
            self.assertLessEqual(len(chunk), 300)
            self.assertEqual(text[start : start + len(chunk)], chunk)
            covered.update(range(start, start + len(chunk)))
        self.assertEqual(covered, set(range(len(text))))
        for (a, ca), (b, _) in zip(ws, ws[1:]):
            self.assertLess(b, a + len(ca), "consecutive windows overlap")

    def test_a_name_across_a_cut_is_whole_in_some_window(self):
        text = "x " * 140 + "Íñigo Pérez" + " y" * 200
        self.assertTrue(any("Íñigo Pérez" in c for _, c in sc.windows(text, size=300, overlap=60)))

    def test_windowed_spans_point_into_the_whole_text_once(self):
        text = "x " * 140 + "Íñigo Pérez" + " y" * 400 + " Íñigo Pérez"
        spans = sc.windowed(text, FakeRuntime().entities, size=300, overlap=60)
        self.assertEqual([text[s:e] for s, e, _ in spans], ["Íñigo Pérez", "Íñigo Pérez"])


class SocketTest(unittest.TestCase):
    def test_serves_one_connection_per_exchange_with_a_private_socket(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "s")
        server = sc.listen(path, sc.Handler(ENTRY, FakeRuntime()))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with socket.socket(socket.AF_UNIX) as c:
            c.connect(path)
            f = c.makefile("rwb")
            for rid, method, params in [(1, "initialize", {"protocolVersion": "1"}), (2, "recognize", {"units": ["Íñigo Pérez"]})]:
                f.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode() + b"\n")
                f.flush()
                self.assertEqual(json.loads(f.readline())["id"], rid)

    def test_replaces_a_stale_socket_but_not_a_file(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "s")
        with open(path, "w") as f:
            f.write("not a socket")
        with self.assertRaises(OSError):
            sc.listen(path, sc.Handler(ENTRY, FakeRuntime()))
        os.unlink(path)
        stale = socket.socket(socket.AF_UNIX)
        stale.bind(path)
        stale.close()
        sc.listen(path, sc.Handler(ENTRY, FakeRuntime())).server_close()


if __name__ == "__main__":
    unittest.main()
