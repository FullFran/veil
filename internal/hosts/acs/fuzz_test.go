package acs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// fuzzServer answers with the real policy (every detector veil ships, an
// in-memory store), so rewrites and denials are reached, not only allows.
func fuzzServer() *Server {
	registry := domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewIBANDetector(),
		domain.NewEmailDetector(),
		domain.NewPhoneDetector(),
		domain.NewSecretPathDetector(),
		domain.NewBinaryContentDetector(),
	)
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())
	return NewServer(port.Config{
		Guard: func(event domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
			decision, err := policy.Evaluate(event)
			if err != nil {
				return domain.Decision{}, nil, problem.CapabilityUnsupported
			}
			return decision, json.RawMessage(`{}`), ""
		},
		Now: func() time.Time { return exampleTime },
	})
}

// addExampleSeeds adds every request example of the pinned ACS spec.
func addExampleSeeds(f *testing.F, wrap func([]byte) []byte) {
	f.Helper()
	paths, err := filepath.Glob(filepath.Join("v0_1", "spec", "examples", "*.request.json"))
	if err != nil || len(paths) == 0 {
		f.Fatalf("no ACS request examples: %v", err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- a fixed glob inside the repository
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wrap(raw))
	}
}

// checkResponse fails unless body is one JSON-RPC 2.0 response object with
// an id member and exactly one of result and error, and an error is always
// reported as a failure.
func checkResponse(t *testing.T, msg []byte, reply port.Reply) {
	t.Helper()
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(reply.Body, &resp); err != nil {
		t.Fatalf("answer to %q is not a JSON object: %v: %s", msg, err, reply.Body)
	}
	if string(resp["jsonrpc"]) != `"2.0"` {
		t.Fatalf("answer to %q has jsonrpc %s", msg, resp["jsonrpc"])
	}
	if _, ok := resp["id"]; !ok {
		t.Fatalf("answer to %q has no id: %s", msg, reply.Body)
	}
	_, hasResult := resp["result"]
	_, hasError := resp["error"]
	if hasResult == hasError {
		t.Fatalf("answer to %q has result=%v error=%v: %s", msg, hasResult, hasError, reply.Body)
	}
	if hasError && reply.Failure == "" {
		t.Fatalf("error answer to %q reports no failure: %s", msg, reply.Body)
	}
}

// FuzzServer_Answer (go test -fuzz): any message, valid ACS or not, gets one
// well-formed JSON-RPC 2.0 response, and never a panic.
func FuzzServer_Answer(f *testing.F) {
	addExampleSeeds(f, func(raw []byte) []byte { return raw })
	for _, seed := range []string{``, `null`, `[]`, `{}`, `{"jsonrpc":"2.0","id":1,"params":{"acs_version":"0.2.0"}}`, `{"id":{"a":1},"params":{"acs_version":1}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		checkResponse(t, msg, fuzzServer().Answer(msg))
	})
}

// FuzzServe (go test -fuzz): any byte stream on the stdio transport is
// either one bare message answered with one JSON line, or Content-Length
// frames each answered with one framed JSON-RPC response; Serve never
// panics and never writes anything else.
func FuzzServe(f *testing.F) {
	addExampleSeeds(f, func(raw []byte) []byte { return raw })
	addExampleSeeds(f, func(raw []byte) []byte { return []byte(frame(raw) + frame(raw)) })
	for _, seed := range []string{
		"Content-Length: abc\r\n\r\n{}",
		"Content-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
		"Content-Length: 999999999\r\n\r\n{}",
		"\r\n\t {}",
		"x",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		var out bytes.Buffer
		server := fuzzServer()
		_ = Serve(bytes.NewReader(input), &out, server.Answer, func(problem.Code) {})
		if !framed(bufio.NewReader(bytes.NewReader(input))) {
			body := out.Bytes()
			if len(body) == 0 || body[len(body)-1] != '\n' || bytes.Count(body, []byte("\n")) != 1 {
				t.Fatalf("bare input %q answered with %q, want one JSON line", input, body)
			}
			checkResponse(t, input, port.Reply{Body: body, Failure: failureOf(body)})
			return
		}
		r := bufio.NewReader(&out)
		for {
			body, err := readFrame(r)
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Fatalf("framed input %q answered with a malformed frame: %v: %q", input, err, out.Bytes())
			}
			checkResponse(t, input, port.Reply{Body: body, Failure: failureOf(body)})
		}
	})
}

// failureOf stands in for the failure a reply reported, which Serve does
// not hand back: an error response's data.reason.
func failureOf(body []byte) problem.Code {
	var resp struct {
		Error *struct {
			Data struct {
				Reason string `json:"reason"`
			} `json:"data"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &resp) != nil || resp.Error == nil {
		return ""
	}
	return problem.Code(resp.Error.Data.Reason)
}
