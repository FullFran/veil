package acs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

var exampleTime = time.Date(2026, 9, 9, 14, 2, 11, 0, time.UTC)

func newServer() *Server {
	return NewServer(port.Config{
		Guard: func(domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
			return domain.AllowDecision(), json.RawMessage(`{}`), ""
		},
		Now: func() time.Time { return exampleTime },
	})
}

func example(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("v0_1", "spec", "examples", "readme-file-read.request.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func errorOf(t *testing.T, reply port.Reply) (int, map[string]any) {
	t.Helper()
	var m struct {
		Error *struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reply.Body, &m); err != nil || m.Error == nil {
		t.Fatalf("not a JSON-RPC error: %s", reply.Body)
	}
	return m.Error.Code, m.Error.Data
}

func TestSupportedVersions(t *testing.T) {
	if got := SupportedVersions(); len(got) != 1 || got[0] != "0.1.0" {
		t.Fatalf("SupportedVersions = %v", got)
	}
}

// TestAnswer_DispatchesByACSVersion hands a known version to its package
// and fails an unknown one closed with UNSUPPORTED_VERSION and the list
// of versions veil speaks.
func TestAnswer_DispatchesByACSVersion(t *testing.T) {
	s := newServer()
	if reply := s.Answer(example(t)); reply.Failure != "" {
		t.Fatalf("known version failed: %s", reply.Body)
	}
	unknown := strings.Replace(string(example(t)), `"acs_version": "0.1.0"`, `"acs_version": "0.2.0"`, 1)
	reply := s.Answer([]byte(unknown))
	code, data := errorOf(t, reply)
	if code != -32001 || reply.Failure != problem.ACSVersionUnsupported || data["reason"] != string(problem.ACSVersionUnsupported) {
		t.Fatalf("unknown version = %d %s %v", code, reply.Failure, data)
	}
	if got, _ := json.Marshal(data["supported_versions"]); string(got) != `["0.1.0"]` {
		t.Fatalf("supported_versions = %s", got)
	}
}

// TestAnswer_MessagesWithoutAVersion_FailClosed covers what cannot be
// dispatched at all.
func TestAnswer_MessagesWithoutAVersion_FailClosed(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		rpc  int
		code problem.Code
	}{
		{"not JSON", `{"jsonrpc"`, -32700, problem.InputInvalid},
		{"empty", ``, -32700, problem.InputInvalid},
		{"batch", `[` + string(example(t)) + `]`, -32600, problem.ACSRequestInvalid},
		{"no params", `{"jsonrpc":"2.0","id":1,"method":"steps/toolCallRequest"}`, -32600, problem.ACSRequestInvalid},
		{"version not a string", `{"jsonrpc":"2.0","id":1,"method":"system/ping","params":{"acs_version":1}}`, -32600, problem.ACSRequestInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := newServer().Answer([]byte(tc.msg))
			code, data := errorOf(t, reply)
			if code != tc.rpc || reply.Failure != tc.code || data["reason"] != string(tc.code) {
				t.Fatalf("= %d %s, want %d %s", code, reply.Failure, tc.rpc, tc.code)
			}
		})
	}
}

// TestServe_BareJSON answers all of stdin as one message, on one line.
func TestServe_BareJSON(t *testing.T) {
	var out bytes.Buffer
	var failures []problem.Code
	if err := Serve(bytes.NewReader(example(t)), &out, newServer().Answer, func(c problem.Code) { failures = append(failures, c) }); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "\n") || strings.Count(out.String(), "\n") != 1 || len(failures) != 0 {
		t.Fatalf("out = %q, failures = %v", out.String(), failures)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || m["result"] == nil {
		t.Fatalf("out = %s", out.String())
	}
}

func frame(body []byte) string {
	return "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
}

// TestServe_ContentLengthFraming answers each framed message with a framed
// response until EOF, and reports each failure.
func TestServe_ContentLengthFraming(t *testing.T) {
	second := strings.Replace(string(example(t)), "b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11", "b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a12", 1)
	in := frame(example(t)) + "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n" + frame([]byte(second)) + frame(example(t))
	var out bytes.Buffer
	var failures []problem.Code
	if err := Serve(strings.NewReader(in), &out, newServer().Answer, func(c problem.Code) { failures = append(failures, c) }); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(&out)
	var decisions []string
	for {
		body, err := readFrame(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Result struct {
				Decision string `json:"decision"`
			} `json:"result"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		if m.Error != nil {
			decisions = append(decisions, fmt.Sprint(m.Error.Code))
		} else {
			decisions = append(decisions, m.Result.Decision)
		}
	}
	if got := strings.Join(decisions, ","); got != "allow,allow,deny" {
		t.Fatalf("answers = %s, want allow,allow,deny (the third replays the first)", got)
	}
	if len(failures) != 1 || failures[0] != problem.ACSReplay {
		t.Fatalf("failures = %v", failures)
	}
}

// TestServe_BrokenFraming_StopsWithAnError answers a parse error and stops
// on a header veil cannot frame.
func TestServe_BrokenFraming_StopsWithAnError(t *testing.T) {
	cases := map[string]string{
		"no length":        "Content-Type: x\r\n\r\n{}",
		"bad length":       "Content-Length: abc\r\n\r\n{}",
		"too long":         "Content-Length: 999999999\r\n\r\n{}",
		"short body":       "Content-Length: 10\r\n\r\n{}",
		"header not a key": "Content-Length: 2\r\nnonsense\r\n\r\n{}",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := Serve(strings.NewReader(in), &out, newServer().Answer, func(problem.Code) {})
			if err == nil {
				t.Fatalf("Serve = nil, want a framing error; out = %q", out.String())
			}
		})
	}
}
