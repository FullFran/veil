package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FullFran/veil/internal/ner"
	"github.com/FullFran/veil/internal/problem"
)

var modelBody = []byte("weights")

// modelEnv serves one test model over TLS, adds it with a user catalog,
// points the cache at a temp dir and returns the cache root and a request
// counter.
func modelEnv(t *testing.T, served []byte) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(served)
	}))
	t.Cleanup(srv.Close)
	previous := modelHTTPClient
	modelHTTPClient = func() *http.Client {
		c := ner.HTTPClient()
		c.Transport = srv.Client().Transport
		return c
	}
	t.Cleanup(func() { modelHTTPClient = previous })

	sum := sha256.Sum256(modelBody)
	entry := map[string]any{
		"id": "test-model", "runtime": "gliner2", "license": "Apache-2.0", "languages": []string{"es"},
		"source": map[string]any{"repo": "example/model", "revision": "r1"},
		"labels": map[string]any{"person": "NOMBRE"},
		"files": []any{map[string]any{
			"path": "model.bin", "url": srv.URL + "/model.bin", "size": len(modelBody),
			"digest": "sha256:" + hex.EncodeToString(sum[:]),
		}},
	}
	doc, _ := json.Marshal(map[string]any{"version": "1.0", "models": []any{entry}})
	catalog := filepath.Join(t.TempDir(), "models.json")
	if err := os.WriteFile(catalog, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	t.Setenv("VEIL_NER_CATALOG", catalog)
	t.Setenv("VEIL_MODEL_CACHE", cache)
	t.Setenv("VEIL_NER_MODEL", "")
	t.Setenv("VEIL_POLICY", "")
	return cache, &hits
}

func runModelCmd(t *testing.T, args ...string) (int, []map[string]any, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"model"}, args...), strings.NewReader(""), &stdout, &stderr)
	var lines []map[string]any
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			t.Fatalf("stdout line %q is not JSON: %v", scanner.Text(), err)
		}
		lines = append(lines, m)
	}
	return code, lines, stderr.String()
}

func byID(lines []map[string]any, id string) map[string]any {
	for _, l := range lines {
		if l["id"] == id {
			return l
		}
	}
	return nil
}

func TestModelList_EveryEntryAndWhetherItIsCached(t *testing.T) {
	modelEnv(t, modelBody)

	code, lines, _ := runModelCmd(t, "list")
	if code != 0 || byID(lines, "gliner2-pii") == nil || byID(lines, "spacy-es-core-news-lg") == nil {
		t.Fatalf("exit %d, lines %v; want every catalog entry", code, lines)
	}
	test := byID(lines, "test-model")
	if test == nil || test["present"] != false || test["license"] != "Apache-2.0" || test["bytes"] != float64(len(modelBody)) {
		t.Fatalf("test-model = %v, want licence, size and not present", test)
	}

	if code, _, stderr := runModelCmd(t, "pull", "test-model", "--accept-license", "Apache-2.0"); code != 0 {
		t.Fatalf("pull: exit %d, %s", code, stderr)
	}
	_, lines, _ = runModelCmd(t, "list")
	if byID(lines, "test-model")["present"] != true {
		t.Fatal("test-model not present after pull")
	}
}

func TestModelPull_LicenceMustBeAcceptedByItsSPDXId(t *testing.T) {
	for _, args := range [][]string{
		{"pull", "test-model"},
		{"pull", "test-model", "--accept-license", "MIT"},
	} {
		_, hits := modelEnv(t, modelBody)
		code, lines, stderr := runModelCmd(t, args...)
		if code != problem.ExitFailedClosed || hits.Load() != 0 {
			t.Fatalf("%v: exit %d, %d downloads; want a refusal before any download", args, code, hits.Load())
		}
		if len(lines) != 1 || lines[0]["license"] != "Apache-2.0" {
			t.Fatalf("%v: stdout %v, want the licence printed first", args, lines)
		}
		assertProblem(t, stderr, problem.ModelLicenseNotAccepted)
	}
}

func TestModelPull_ThenVerify(t *testing.T) {
	cache, _ := modelEnv(t, modelBody)

	code, lines, stderr := runModelCmd(t, "pull", "test-model", "--accept-license=Apache-2.0")
	if code != 0 || len(lines) != 2 || lines[1]["verified"] != true {
		t.Fatalf("pull: exit %d, lines %v, stderr %s", code, lines, stderr)
	}
	dir := filepath.Join(cache, "test-model", "r1")
	if lines[1]["dir"] != dir {
		t.Fatalf("dir = %v, want %s", lines[1]["dir"], dir)
	}
	if code, lines, _ := runModelCmd(t, "verify", "test-model"); code != 0 || lines[0]["verified"] != true {
		t.Fatalf("verify: exit %d, %v", code, lines)
	}

	if err := os.WriteFile(filepath.Join(dir, "model.bin"), []byte("WEIGHTS"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runModelCmd(t, "verify", "test-model")
	if code != problem.ExitFailedClosed {
		t.Fatalf("verify tampered: exit %d", code)
	}
	assertProblem(t, stderr, problem.ModelDigestMismatch)
}

func TestModelVerify_DefaultsToTheSelectedModel(t *testing.T) {
	modelEnv(t, modelBody)
	t.Setenv("VEIL_POLICY", writePolicy(t, `{"version":"1.0","detectors":{"ner":{"action":"rewrite"}}}`))
	t.Setenv("VEIL_NER_MODEL", "test-model")

	code, _, stderr := runModelCmd(t, "verify")
	if code != problem.ExitFailedClosed {
		t.Fatalf("exit %d", code)
	}
	assertProblem(t, stderr, problem.ModelMissing)
}

func TestModel_Failures(t *testing.T) {
	cases := map[string]struct {
		served []byte
		args   []string
		exit   int
		want   problem.Code
	}{
		"no subcommand":         {modelBody, nil, problem.ExitUsage, problem.Usage},
		"unknown subcommand":    {modelBody, []string{"run"}, problem.ExitUsage, problem.Usage},
		"pull without id":       {modelBody, []string{"pull"}, problem.ExitUsage, problem.Usage},
		"verify, none selected": {modelBody, []string{"verify"}, problem.ExitUsage, problem.Usage},
		"unknown model":         {modelBody, []string{"verify", "nope"}, problem.ExitFailedClosed, problem.ModelUnknown},
		"tampered download":     {[]byte("WEIGHTS"), []string{"pull", "test-model", "--accept-license", "Apache-2.0"}, problem.ExitFailedClosed, problem.ModelDigestMismatch},
		"empty download":        {nil, []string{"pull", "test-model", "--accept-license", "Apache-2.0"}, problem.ExitFailedClosed, problem.ModelDigestMismatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			modelEnv(t, tc.served)
			code, _, stderr := runModelCmd(t, tc.args...)
			if code != tc.exit {
				t.Fatalf("exit %d, want %d", code, tc.exit)
			}
			assertProblem(t, stderr, tc.want)
		})
	}
}

func TestModelPull_UntrustedServerIsADownloadFailure(t *testing.T) {
	modelEnv(t, modelBody)
	// The system roots do not trust the test server's certificate.
	modelHTTPClient = ner.HTTPClient
	code, _, stderr := runModelCmd(t, "pull", "test-model", "--accept-license", "Apache-2.0")
	if code != problem.ExitFailedClosed {
		t.Fatalf("exit %d", code)
	}
	assertProblem(t, stderr, problem.ModelDownload)
}
