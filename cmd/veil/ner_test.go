package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/ner"
	"github.com/FullFran/veil/internal/problem"
)

const nerName = "Ana Ruiz"

// fakeSidecar serves model on a fresh Unix socket: it reports model in
// initialize and answers recognize with a person span on every occurrence
// of nerName. It returns the socket path.
func fakeSidecar(t *testing.T, model ner.Model) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveFake(conn, model)
		}
	}()
	return socket
}

func serveFake(conn net.Conn, model ner.Model) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Units []string `json:"units"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &req) != nil {
			return
		}
		var result any = map[string]any{"protocolVersion": ner.ProtocolVersion, "model": model}
		if req.Method == "recognize" {
			spans := make([][]map[string]any, len(req.Params.Units))
			for i, u := range req.Params.Units {
				spans[i] = []map[string]any{}
				if at := strings.Index(u, nerName); at >= 0 {
					spans[i] = append(spans[i], map[string]any{"start": at, "end": at + len(nerName), "label": "person"})
				}
			}
			result = map[string]any{"spans": spans}
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if _, err := conn.Write(append(out, '\n')); err != nil {
			return
		}
	}
}

func gliner(t *testing.T) ner.Entry {
	t.Helper()
	c, err := ner.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.Lookup("gliner2-pii")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// nerEnv isolates a run with a policy that enables ner with action.
func nerEnv(t *testing.T, action, model string) string {
	t.Helper()
	path := evidenceEnv(t)
	t.Setenv("VEIL_NER_MODEL", "")
	t.Setenv("VEIL_NER_CATALOG", "")
	t.Setenv("VEIL_NER_SOCKET", "")
	member := ""
	if model != "" {
		member = `,"model":"` + model + `"`
	}
	t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"dni":{"action":"rewrite"},"ner":{"action":"`+action+`"`+member+`}}}`))
	return path
}

const nerTool = `{"event":"tool.execute.before","sessionID":"s1","tool":"bash","args":{"command":"echo Ana Ruiz 12345678Z"}}`

func runNER(t *testing.T, payload string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"opencode"}, strings.NewReader(payload), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRun_NER_RewritesTheNameAndRecordsTheModel(t *testing.T) {
	evidencePath := nerEnv(t, "rewrite", "gliner2-pii")
	entry := gliner(t)
	t.Setenv("VEIL_NER_SOCKET", fakeSidecar(t, entry.Model()))

	code, stdout, stderr := runNER(t, nerTool)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q; want a rewrite", code, stderr)
	}
	if strings.Contains(stdout, nerName) || strings.Contains(stdout, "12345678Z") || !strings.Contains(stdout, "[NOMBRE-001]") {
		t.Fatalf("stdout = %s, want the name and the DNI pseudonymized", stdout)
	}
	records := readRecords(t, evidencePath)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	got := member(t, records[0], "data", "unmapped", "veil", "ner_model")
	want := map[string]any{"id": entry.ID, "revision": entry.Source.Revision, "entry_digest": entry.Digest()}
	if g, _ := json.Marshal(got); string(g) != mustJSON(t, want) {
		t.Fatalf("ner_model = %s, want %s", g, mustJSON(t, want))
	}
	raw, _ := json.Marshal(records[0])
	if strings.Contains(string(raw), "Ana") || !strings.Contains(string(raw), "https://w3id.org/dpv/pd#Name") {
		t.Fatalf("record = %s, want the Name category and no name text", raw)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRun_NER_DenyActionBlocks(t *testing.T) {
	nerEnv(t, "deny", "gliner2-pii")
	t.Setenv("VEIL_NER_SOCKET", fakeSidecar(t, gliner(t).Model()))

	code, stdout, _ := runNER(t, `{"event":"tool.execute.before","sessionID":"s1","tool":"bash","args":{"command":"echo Ana Ruiz"}}`)
	var answer map[string]any
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
	if code != 0 || answer["action"] != "deny" {
		t.Fatalf("exit %d, answer %v; want a deny decision", code, answer)
	}
}

func TestRun_NER_ModelFromEnv(t *testing.T) {
	nerEnv(t, "rewrite", "")
	t.Setenv("VEIL_NER_MODEL", "gliner2-pii")
	t.Setenv("VEIL_NER_SOCKET", fakeSidecar(t, gliner(t).Model()))

	if code, stdout, stderr := runNER(t, nerTool); code != 0 || strings.Contains(stdout, nerName) {
		t.Fatalf("exit %d, stdout %s, stderr %s; want the name rewritten", code, stdout, stderr)
	}
}

func TestRun_NER_FailsClosed(t *testing.T) {
	userCatalog := filepath.Join(t.TempDir(), "models.json")
	if err := os.WriteFile(userCatalog, []byte(`{"version":"1.0","models":[{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		setup func(t *testing.T)
		want  problem.Code
	}{
		"no sidecar": {func(t *testing.T) {
			t.Setenv("VEIL_NER_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
		}, problem.NERUnavailable},
		"sidecar serves another model": {func(t *testing.T) {
			m := gliner(t).Model()
			m.Revision = strings.Repeat("0", 40)
			t.Setenv("VEIL_NER_SOCKET", fakeSidecar(t, m))
		}, problem.NERModelMismatch},
		"unknown model": {func(t *testing.T) {
			t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"ner":{"action":"rewrite","model":"nope"}}}`))
		}, problem.ModelUnknown},
		"invalid catalog":      {func(t *testing.T) { t.Setenv("VEIL_NER_CATALOG", userCatalog) }, problem.ModelCatalogInvalid},
		"env and policy model": {func(t *testing.T) { t.Setenv("VEIL_NER_MODEL", "gliner2-pii") }, problem.PolicyInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			nerEnv(t, "rewrite", "gliner2-pii")
			tc.setup(t)
			code, stdout, stderr := runNER(t, nerTool)
			if code != ocFailed || stdout != "" {
				t.Fatalf("exit %d, stdout %q; want failed closed", code, stdout)
			}
			assertProblem(t, stderr, tc.want)
		})
	}
}
