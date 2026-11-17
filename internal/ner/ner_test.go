package ner_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/ner"
)

var testModel = ner.Model{ID: "gliner2-pii", Revision: "1cb4166094dc58fa8d836429f060d6c95f62b495", EntryDigest: "sha256:" + strings.Repeat("a", 64)}

// request is one JSON-RPC request line the fake sidecar received.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// answer builds the reply line to one request. Returning "" closes the
// connection without answering; returning hang makes the fake read on
// and never answer.
type answer func(req request) string

const hang = "\x00hang"

// sidecar is a fake NER sidecar on a Unix socket: no model, scripted
// answers, and a record of every request it received.
type sidecar struct {
	socket   string
	answer   answer
	requests chan request
}

// newSidecar listens on a fresh socket. Its path is short on purpose: a
// Unix socket path is limited to about 104 bytes.
func newSidecar(t *testing.T, a answer) *sidecar {
	t.Helper()
	dir, err := os.MkdirTemp("", "ner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s := &sidecar{socket: filepath.Join(dir, "s"), answer: a, requests: make(chan request, 16)}
	l, err := net.Listen("unix", s.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// A sidecar makes its socket private, whatever the umask.
	if err := os.Chmod(s.socket, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *sidecar) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			return
		}
		s.requests <- req
		reply := s.answer(req)
		switch reply {
		case "":
			return
		case hang:
			_, _ = r.ReadBytes('\n')
			return
		}
		if _, err := conn.Write([]byte(reply + "\n")); err != nil {
			return
		}
	}
}

// next returns the next request the fake received, failing the test if
// none arrives in time.
func (s *sidecar) next(t *testing.T) request {
	t.Helper()
	select {
	case req := <-s.requests:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("the sidecar received no request")
		return request{}
	}
}

func result(req request, v any) string {
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": v})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func initResult(req request, m ner.Model) string {
	return result(req, map[string]any{"protocolVersion": ner.ProtocolVersion, "model": m})
}

// spansFor answers initialize with testModel and recognize with spans.
func spansFor(spans any) answer {
	return func(req request) string {
		if req.Method == "initialize" {
			return initResult(req, testModel)
		}
		return result(req, map[string]any{"spans": spans})
	}
}

type span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Label string `json:"label"`
}

func detector(socket string) *ner.Detector {
	return ner.NewDetector(ner.Config{
		Socket:  socket,
		Timeout: 500 * time.Millisecond,
		Model:   testModel,
		Labels:  map[string]string{"person": "NOMBRE"},
	})
}

func prompt(text string) domain.Event {
	return domain.Event{Kind: domain.EventPromptSubmit, Host: domain.HostClaudeCode, Text: text}
}

func TestDetect_SpansBecomeNombreFindings(t *testing.T) {
	text := "Habla con Íñigo Pérez mañana"
	start := strings.Index(text, "Íñigo")
	end := start + len("Íñigo Pérez")
	s := newSidecar(t, spansFor([][]span{{{start, end, "person"}}}))

	findings, err := detector(s.socket).Detect(prompt(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1", findings)
	}
	f := findings[0]
	if f.Detector != ner.DetectorName || f.Category != "NOMBRE" || f.Match != "Íñigo Pérez" || f.Redacted != "[NOMBRE]" {
		t.Fatalf("finding = %+v, want a NOMBRE finding matching the span", f)
	}
}

func TestDetect_SpeaksTheVersionedProtocol(t *testing.T) {
	s := newSidecar(t, spansFor([][]span{{}}))

	if _, err := detector(s.socket).Detect(prompt("hola")); err != nil {
		t.Fatal(err)
	}
	init, rec := s.next(t), s.next(t)
	if init.JSONRPC != "2.0" || init.Method != "initialize" {
		t.Fatalf("first request = %+v, want a JSON-RPC 2.0 initialize", init)
	}
	var ip struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(init.Params, &ip); err != nil || ip.ProtocolVersion != ner.ProtocolVersion {
		t.Fatalf("initialize params = %s, want protocolVersion %q", init.Params, ner.ProtocolVersion)
	}
	if rec.JSONRPC != "2.0" || rec.Method != "recognize" {
		t.Fatalf("second request = %+v, want a JSON-RPC 2.0 recognize", rec)
	}
	var rp struct {
		Units []string `json:"units"`
	}
	if err := json.Unmarshal(rec.Params, &rp); err != nil || len(rp.Units) != 1 || rp.Units[0] != "hola" {
		t.Fatalf("recognize params = %s, want units [\"hola\"]", rec.Params)
	}
}

func TestDetect_ToolFieldsAreTheUnits(t *testing.T) {
	s := newSidecar(t, spansFor([][]span{{}, {{0, 3, "person"}}}))
	event := domain.Event{
		Kind:   domain.EventToolArgs,
		Host:   domain.HostClaudeCode,
		Text:   "flattened",
		Fields: map[string]string{"b": "Ana", "a": "nota", "empty": ""},
	}

	findings, err := detector(s.socket).Detect(event)
	if err != nil {
		t.Fatal(err)
	}
	s.next(t)
	rec := s.next(t)
	var rp struct {
		Units []string `json:"units"`
	}
	if err := json.Unmarshal(rec.Params, &rp); err != nil {
		t.Fatal(err)
	}
	if strings.Join(rp.Units, "|") != "nota|Ana" {
		t.Fatalf("units = %q, want the non-empty field values ordered by key", rp.Units)
	}
	if len(findings) != 1 || findings[0].Match != "Ana" {
		t.Fatalf("findings = %+v, want Ana from the second unit", findings)
	}
}

func TestDetect_NothingToScan_DoesNotDial(t *testing.T) {
	findings, err := detector("/nonexistent/veil-ner.sock").Detect(prompt(""))
	if err != nil || findings != nil {
		t.Fatalf("Detect(empty) = %+v, %v, want nothing and no error", findings, err)
	}
}

func TestDetect_NoSidecar_IsUnavailable(t *testing.T) {
	dir, err := os.MkdirTemp("", "ner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	_, err = detector(filepath.Join(dir, "missing")).Detect(prompt("hola"))
	if !errors.Is(err, ner.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestDetect_SilentSidecar_TimesOut(t *testing.T) {
	s := newSidecar(t, func(request) string { return hang })

	start := time.Now()
	_, err := detector(s.socket).Detect(prompt("hola"))
	if !errors.Is(err, ner.ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Detect took %v, want it bounded by the 500 ms timeout", elapsed)
	}
}

func TestDetect_SidecarClosesMidExchange_IsCrashed(t *testing.T) {
	for _, method := range []string{"initialize", "recognize"} {
		t.Run(method, func(t *testing.T) {
			s := newSidecar(t, func(req request) string {
				if req.Method == method {
					return ""
				}
				return initResult(req, testModel)
			})
			if _, err := detector(s.socket).Detect(prompt("hola")); !errors.Is(err, ner.ErrCrashed) {
				t.Fatalf("err = %v, want ErrCrashed", err)
			}
		})
	}
}

func TestDetect_ModelMismatch(t *testing.T) {
	for name, m := range map[string]ner.Model{
		"id":       {ID: "other", Revision: testModel.Revision, EntryDigest: testModel.EntryDigest},
		"revision": {ID: testModel.ID, Revision: strings.Repeat("0", 40), EntryDigest: testModel.EntryDigest},
		"entry":    {ID: testModel.ID, Revision: testModel.Revision, EntryDigest: "sha256:" + strings.Repeat("b", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSidecar(t, func(req request) string { return initResult(req, m) })
			if _, err := detector(s.socket).Detect(prompt("hola")); !errors.Is(err, ner.ErrModelMismatch) {
				t.Fatalf("err = %v, want ErrModelMismatch", err)
			}
		})
	}
}

func TestDetect_ProtocolErrors(t *testing.T) {
	text := "Ñandú Ruiz"
	ok := func(req request) string { return initResult(req, testModel) }
	onRecognize := func(reply func(req request) string) answer {
		return func(req request) string {
			if req.Method == "initialize" {
				return ok(req)
			}
			return reply(req)
		}
	}
	spans := func(v any) answer {
		return onRecognize(func(req request) string { return result(req, map[string]any{"spans": v}) })
	}
	cases := map[string]answer{
		"not JSON":     func(request) string { return "{not json" },
		"not JSON-RPC": func(req request) string { return `{"jsonrpc":"1.0","id":` + string(req.ID) + `,"result":{}}` },
		"wrong id":     func(request) string { return `{"jsonrpc":"2.0","id":99,"result":{}}` },
		"error reply": func(req request) string {
			return `{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32603,"message":"x"}}`
		},
		"no result": func(req request) string { return `{"jsonrpc":"2.0","id":` + string(req.ID) + `}` },
		"other version": func(req request) string {
			return result(req, map[string]any{"protocolVersion": "2", "model": testModel})
		},
		"span count":    spans([][]span{}),
		"empty span":    spans([][]span{{{3, 3, "person"}}}),
		"negative":      spans([][]span{{{-1, 3, "person"}}}),
		"past the end":  spans([][]span{{{0, len(text) + 1, "person"}}}),
		"mid rune":      spans([][]span{{{1, 5, "person"}}}),
		"label":         spans([][]span{{{0, 6, "location"}}}),
		"line too long": onRecognize(func(req request) string { return `{"x":"` + strings.Repeat("a", 17<<20) + `"}` }),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSidecar(t, a)
			d := ner.NewDetector(ner.Config{Socket: s.socket, Timeout: 5 * time.Second, Model: testModel, Labels: map[string]string{"person": "NOMBRE"}})
			if _, err := d.Detect(prompt(text)); !errors.Is(err, ner.ErrProtocol) {
				t.Fatalf("err = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDetect_OverlappingOrAdjacentSpansAreOneFinding(t *testing.T) {
	const text = "Hola Ana Ruiz López fin" // UTF-8 byte offsets: "ó" is two bytes
	cases := map[string][]span{
		"left first":  {{5, 13, "person"}, {9, 20, "person"}},
		"right first": {{9, 20, "person"}, {5, 13, "person"}},
		"adjacent":    {{5, 9, "person"}, {9, 20, "person"}},
		"nested":      {{9, 13, "person"}, {5, 20, "person"}},
	}
	for name, spans := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSidecar(t, spansFor([][]span{spans}))
			findings, err := detector(s.socket).Detect(prompt(text))
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].Match != "Ana Ruiz López" || findings[0].Category != "NOMBRE" {
				t.Fatalf("findings = %+v, want one NOMBRE finding for the whole run", findings)
			}
		})
	}
}

func TestDetect_TooManySpans_IsAProtocolErrorWithinTheTimeout(t *testing.T) {
	cases := map[string]int{"over the cap": ner.MaxSpansPerUnit + 1, "hostile": 200000}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			spans := make([]span, n)
			for i := range spans {
				spans[i] = span{0, 4, "person"}
			}
			s := newSidecar(t, spansFor([][]span{spans}))
			d := ner.NewDetector(ner.Config{Socket: s.socket, Timeout: 2 * time.Second, Model: testModel, Labels: map[string]string{"person": "NOMBRE"}})
			start := time.Now()
			_, err := d.Detect(prompt("Ana Ruiz"))
			// Rejected by the cap, or, where decoding the answer alone
			// outlasts the timeout (a slow or instrumented machine), timed
			// out: never later than the timeout.
			timedOut := n > ner.MaxSpansPerUnit+1 && errors.Is(err, ner.ErrTimeout)
			if !errors.Is(err, ner.ErrProtocol) && !timedOut {
				t.Fatalf("err = %v, want ErrProtocol", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second+250*time.Millisecond {
				t.Fatalf("Detect took %v, want it within the 2 s timeout", elapsed)
			}
		})
	}
}

func TestDetect_UnsafeSocket_IsUnavailable(t *testing.T) {
	cases := map[string]func(t *testing.T, s *sidecar){
		"world-writable socket": func(t *testing.T, s *sidecar) {
			if err := os.Chmod(s.socket, 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable directory": func(t *testing.T, s *sidecar) {
			if err := os.Chmod(filepath.Dir(s.socket), 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"not a socket": func(t *testing.T, s *sidecar) {
			s.socket = filepath.Join(filepath.Dir(s.socket), "file")
			if err := os.WriteFile(s.socket, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink to the socket": func(t *testing.T, s *sidecar) {
			link := filepath.Join(filepath.Dir(s.socket), "link")
			if err := os.Symlink(s.socket, link); err != nil {
				t.Fatal(err)
			}
			s.socket = link
		},
	}
	for name, unsafe := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSidecar(t, spansFor([][]span{{}}))
			unsafe(t, s)
			if _, err := detector(s.socket).Detect(prompt("hola")); !errors.Is(err, ner.ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
			select {
			case req := <-s.requests:
				t.Fatalf("veil sent %s to an unsafe socket", req.Method)
			default:
			}
		})
	}
}
