package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/hosts/claudecode"
	"github.com/FullFran/veil/internal/hosts/opencode"
	"github.com/FullFran/veil/internal/problem"
)

// brokenWriter fails every write, like a closed pipe.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// An answer that never reaches the host must not leave a success exit code
// behind: Claude Code treats exit 0 with no stdout as "proceed unchanged",
// which would send the original, unredacted input on.
func TestRun_UnwritableStdout_FailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		stdin    string
		wantExit int
	}{
		{"claude-code rewrite", []string{"claude-code"},
			`{"hook_event_name": "UserPromptSubmit", "session_id": "sess-1", "user_input": "DNI 12345678Z"}`,
			claudecode.FailureExitCode},
		{"opencode rewrite", []string{"opencode"},
			`{"event": "tool.execute.before", "sessionID": "ses-1", "tool": "bash", "args": {"command": "echo 12345678Z"}}`,
			opencode.FailureExitCode},
		{"policy", []string{"policy"}, "", problem.ExitFailedClosed},
		{"store reveal", []string{"store", "reveal", "never-seen"}, "", problem.ExitFailedClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			var stderr bytes.Buffer

			exit := run(tc.args, strings.NewReader(tc.stdin), brokenWriter{}, &stderr)

			if exit != tc.wantExit {
				t.Fatalf("exit = %d, want %d (failed closed)", exit, tc.wantExit)
			}
			assertProblem(t, stderr.String(), problem.Internal)
		})
	}
}
