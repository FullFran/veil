package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/problem"
)

// acsRequest is a steps/toolCallRequest for tool with args, stamped now so
// it is inside the skew window, with requestID as its request_id.
func acsRequest(t *testing.T, version, requestID, tool string, args map[string]string) string {
	t.Helper()
	arguments := map[string]any{}
	for k, v := range args {
		arguments[k] = map[string]any{"value": v}
	}
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "steps/toolCallRequest",
		"params": map[string]any{
			"acs_version": version,
			"request_id":  requestID,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
			"metadata":    map[string]any{"agent_id": "test", "session_id": "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22"},
			"payload":     map[string]any{"tool": map[string]any{"name": tool}, "arguments": arguments},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const acsRequestID = "b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11"

// isolateACS points every key source veil reads at nothing the machine
// running the test owns.
func isolateACS(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv(acsKeyIDEnv, "")
	t.Setenv(acsKeyFDEnv, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
}

type acsAnswer struct {
	Result *struct {
		Decision      string         `json:"decision"`
		ReasonCodes   []string       `json:"reason_codes"`
		Modifications map[string]any `json:"modifications"`
		PolicyData    struct {
			Veil struct {
				Evidence map[string]any `json:"evidence"`
			} `json:"veil"`
		} `json:"policy_data"`
	} `json:"result"`
	Error *struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	} `json:"error"`
}

func runACSWith(t *testing.T, stdin string) (int, acsAnswer, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := run([]string{"acs"}, strings.NewReader(stdin), &stdout, &stderr)
	var a acsAnswer
	if err := json.Unmarshal(stdout.Bytes(), &a); err != nil {
		t.Fatalf("stdout is not one JSON-RPC response: %q", stdout.String())
	}
	return exit, a, stderr.String()
}

// TestRun_ACS_Decisions maps veil's decisions on a tool call: a clean call
// is allowed, a DNI is rewritten through parameter_overrides, a secret
// file is denied. Each carries the evidence record and exits 0.
func TestRun_ACS_Decisions(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]string
		want string
	}{
		{"clean call", "read", map[string]string{"filePath": "/home/user/notes.md"}, "allow"},
		{"DNI in arguments", "bash", map[string]string{"command": "echo 12345678Z"}, "modify"},
		{"secret file", "read", map[string]string{"filePath": "/home/user/project/.env"}, "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateACS(t)
			exit, a, stderr := runACSWith(t, acsRequest(t, "0.1.0", acsRequestID, tc.tool, tc.args))
			if exit != problem.ExitDecision || stderr != "" {
				t.Fatalf("exit = %d, stderr = %q, want a decision", exit, stderr)
			}
			if a.Result == nil || a.Result.Decision != tc.want {
				t.Fatalf("answer = %+v, want %s", a, tc.want)
			}
			if a.Result.PolicyData.Veil.Evidence["specversion"] != "1.0" {
				t.Fatalf("evidence = %v, want a CloudEvents record", a.Result.PolicyData.Veil.Evidence)
			}
			if tc.want == "modify" {
				overrides, _ := json.Marshal(a.Result.Modifications["parameter_overrides"])
				if strings.Contains(string(overrides), "12345678Z") || !strings.Contains(string(overrides), "command") {
					t.Fatalf("parameter_overrides = %s, want the command without the DNI", overrides)
				}
			}
		})
	}
}

// TestRun_ACS_FailsClosed covers the failures the acs mode adds: each is
// one problem line on stderr, exit 1, and an answer that is never allow.
func TestRun_ACS_FailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		setup func(t *testing.T)
		rpc   int // 0: a deny decision
		code  problem.Code
	}{
		{
			name:  "unknown acs_version",
			stdin: acsRequest(t, "0.9.0", acsRequestID, "read", map[string]string{"filePath": "a"}),
			rpc:   -32001, code: problem.ACSVersionUnsupported,
		},
		{
			name:  "unmapped hook",
			stdin: strings.Replace(acsRequest(t, "0.1.0", acsRequestID, "read", map[string]string{"filePath": "a"}), "steps/toolCallRequest", "steps/sessionStart", 1),
			rpc:   -32003, code: problem.ACSMethodUnsupported,
		},
		{
			name:  "unsigned while a secret is configured",
			stdin: acsRequest(t, "0.1.0", acsRequestID, "read", map[string]string{"filePath": "a"}),
			setup: func(t *testing.T) {
				dir := t.TempDir()
				secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
				if err := os.WriteFile(filepath.Join(dir, acsCredentialName), []byte(secret+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("CREDENTIALS_DIRECTORY", dir)
				t.Setenv(acsKeyIDEnv, "k1")
			},
			rpc: -32004, code: problem.ACSSignatureInvalid,
		},
		{
			name:  "key id without a secret",
			stdin: acsRequest(t, "0.1.0", acsRequestID, "read", map[string]string{"filePath": "a"}),
			setup: func(t *testing.T) { t.Setenv(acsKeyIDEnv, "k1") },
			code:  problem.ACSKeyInvalid,
		},
		{
			name:  "unreadable policy",
			stdin: acsRequest(t, "0.1.0", acsRequestID, "read", map[string]string{"filePath": "a"}),
			setup: func(t *testing.T) { t.Setenv("VEIL_POLICY", filepath.Join(t.TempDir(), "missing.json")) },
			code:  problem.PolicyUnreadable,
		},
		{
			name:  "not JSON",
			stdin: `{"jsonrpc":`,
			rpc:   -32700, code: problem.InputInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateACS(t)
			if tc.setup != nil {
				tc.setup(t)
			}
			exit, a, stderr := runACSWith(t, tc.stdin)
			if exit != problem.ExitFailedClosed {
				t.Fatalf("exit = %d, want %d", exit, problem.ExitFailedClosed)
			}
			assertProblem(t, stderr, tc.code)
			if tc.rpc == 0 {
				if a.Result == nil || a.Result.Decision != "deny" || len(a.Result.ReasonCodes) != 1 || a.Result.ReasonCodes[0] != string(tc.code) {
					t.Fatalf("answer = %+v, want a deny with reason code %s", a.Result, tc.code)
				}
				return
			}
			if a.Error == nil || a.Error.Code != tc.rpc || a.Error.Data["reason"] != string(tc.code) {
				t.Fatalf("answer = %+v, want JSON-RPC error %d with %s", a.Error, tc.rpc, tc.code)
			}
		})
	}
}

// TestRun_ACS_ExtraArguments_IsUsage keeps the acs mode argument-free.
func TestRun_ACS_ExtraArguments_IsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"acs", "extra"}, strings.NewReader(""), &stdout, &stderr); exit != problem.ExitUsage {
		t.Fatalf("exit = %d, want %d", exit, problem.ExitUsage)
	}
	assertProblem(t, stderr.String(), problem.Usage)
}

// TestLoadACSSecret covers every way the out-of-band secret is configured.
func TestLoadACSSecret(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))
	credential := func(t *testing.T, content string) string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, acsCredentialName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	fd := func(t *testing.T, content string) string {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		// loadACSSecret closes the descriptor it is given, so hand it a
		// duplicate: closing f's own descriptor twice could close one
		// another test has reused in between.
		dup, err := syscall.Dup(int(f.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		return strconv.Itoa(dup)
	}
	cases := []struct {
		name    string
		env     func(t *testing.T) map[string]string
		wantKey bool
		wantErr bool
	}{
		{"nothing set", func(*testing.T) map[string]string { return nil }, false, false},
		{"credential", func(t *testing.T) map[string]string {
			return map[string]string{acsKeyIDEnv: "k1", "CREDENTIALS_DIRECTORY": credential(t, good+"\n")}
		}, true, false},
		{"descriptor", func(t *testing.T) map[string]string {
			return map[string]string{acsKeyIDEnv: "k1", acsKeyFDEnv: fd(t, good)}
		}, true, false},
		{"key id only", func(*testing.T) map[string]string { return map[string]string{acsKeyIDEnv: "k1"} }, false, true},
		{"secret without key id", func(t *testing.T) map[string]string {
			return map[string]string{"CREDENTIALS_DIRECTORY": credential(t, good)}
		}, false, true},
		{"secret shorter than 32 bytes", func(t *testing.T) map[string]string {
			return map[string]string{acsKeyIDEnv: "k1", "CREDENTIALS_DIRECTORY": credential(t, short)}
		}, false, true},
		{"secret not base64", func(t *testing.T) map[string]string {
			return map[string]string{acsKeyIDEnv: "k1", "CREDENTIALS_DIRECTORY": credential(t, "!!not base64!!")}
		}, false, true},
		{"descriptor is stdin", func(*testing.T) map[string]string {
			return map[string]string{acsKeyIDEnv: "k1", acsKeyFDEnv: "0"}
		}, false, true},
		{"descriptor not a number", func(*testing.T) map[string]string {
			return map[string]string{acsKeyIDEnv: "k1", acsKeyFDEnv: "x"}
		}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env(t)
			secret, err := loadACSSecret(func(k string) string { return env[k] })
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if (secret != nil) != tc.wantKey {
				t.Fatalf("secret set = %v, want %v", secret != nil, tc.wantKey)
			}
			if secret != nil && (secret.KeyID != "k1" || len(secret.Bytes) != 32) {
				t.Fatalf("secret = key_id %q, %d bytes", secret.KeyID, len(secret.Bytes))
			}
		})
	}
}
