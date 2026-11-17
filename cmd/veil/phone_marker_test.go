package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/problem"
	"github.com/FullFran/veil/internal/pseudonymstore"
)

// Issue #27: one Spanish phone written bare and with its country code is
// one marker on every host mode, keyed by its E.164 form. Values are
// synthetic.
const onePhoneManyForms = "a 612345678 b +34 612 345 678 c 0034612345678 d (+34) 612-345-678"

var onePhoneWritten = []string{"612345678", "612 345 678", "612-345-678"}

// assertOnePhoneMarker checks out holds [TEL-001] and no second TEL marker,
// and none of the written forms.
func assertOnePhoneMarker(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "[TEL-001]") || strings.Contains(out, "[TEL-002]") {
		t.Errorf("output = %s, want every form as [TEL-001] and no [TEL-002]", out)
	}
	for _, w := range onePhoneWritten {
		if strings.Contains(out, w) {
			t.Errorf("output still contains %q: %s", w, out)
		}
	}
}

func TestRun_OpenCode_OnePhoneEveryForm_OneMarker(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	stdin := `{"event": "chat.message", "sessionID": "ses-1", "fields": {"0": ` + jsonString(t, onePhoneManyForms) + `}}`
	if exit := run([]string{"opencode"}, strings.NewReader(stdin), &stdout, &stderr); exit != 0 {
		t.Fatalf("exit = %d, stderr = %q, want 0", exit, stderr.String())
	}
	assertOnePhoneMarker(t, stdout.String())

	// The marker rehydrates to the first form written in a write tool.
	stdout.Reset()
	write := `{"event": "tool.execute.before", "sessionID": "ses-1", "tool": "write", "args": {"filePath": "notes.txt", "content": "tel [TEL-001]"}}`
	if exit := run([]string{"opencode"}, strings.NewReader(write), &stdout, &stderr); exit != 0 {
		t.Fatalf("write exit = %d, stderr = %q, want 0", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "tel 612345678") {
		t.Errorf("write output = %s, want [TEL-001] rehydrated to 612345678", stdout.String())
	}

	// find reports the session whichever way the phone is written.
	want := []pseudonymstore.Holding{{Session: "ses-1", Categories: []string{"TEL"}}}
	for _, value := range []string{"612345678", "+34 612 345 678", "0034612345678", "(+34) 612-345-678"} {
		exit, out, errOut := storeCmd("find", "--value", value)
		if exit != problem.ExitDecision || errOut != "" {
			t.Fatalf("find %q = (exit %d, stderr %q), want (0, empty)", value, exit, errOut)
		}
		if got := found(t, out); !reflect.DeepEqual(got, want) {
			t.Errorf("find %q = %+v, want %+v", value, got, want)
		}
	}
}

func TestRun_ClaudeCode_OnePhoneEveryForm_OneMarker(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	stdin := `{"hook_event_name": "UserPromptSubmit", "session_id": "sess-1", "user_input": ` + jsonString(t, onePhoneManyForms) + `}`
	if exit := run([]string{"claude-code"}, strings.NewReader(stdin), &stdout, &stderr); exit != 0 {
		t.Fatalf("exit = %d, stderr = %q, want 0", exit, stderr.String())
	}
	assertOnePhoneMarker(t, stdout.String())
}

func TestRun_ACS_OnePhoneEveryForm_OneMarker(t *testing.T) {
	isolateACS(t)
	payload := map[string]any{"content": []any{map[string]any{"type": "text", "value": onePhoneManyForms}}}
	exit, a, stderr := runACSWith(t, acsHook(t, "steps/userMessage", payload))
	if exit != problem.ExitDecision || stderr != "" {
		t.Fatalf("exit = %d, stderr = %q, want a decision", exit, stderr)
	}
	if a.Result == nil || a.Result.Decision != "modify" {
		t.Fatalf("answer = %+v, want modify", a)
	}
	redactions, _ := a.Result.Modifications["redactions"].([]any)
	if len(redactions) != 1 {
		t.Fatalf("redactions = %v, want one", a.Result.Modifications)
	}
	replacement, _ := redactions[0].(map[string]any)["replacement"].(string)
	if want := "a [TEL-001] b [TEL-001] c [TEL-001] d [TEL-001]"; replacement != want {
		t.Errorf("replacement = %q, want %q", replacement, want)
	}
}

// TestRun_OpenCode_EditOfAFileWithAPhone_MatchesItsBytes: the model reads
// a file holding 612345678 as [TEL-001]; its edit's oldString must come
// back as the file's own bytes, or the edit no longer matches.
func TestRun_OpenCode_EditOfAFileWithAPhone_MatchesItsBytes(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	read := `{"event": "tool.execute.after", "sessionID": "ses-1", "tool": "read", "fields": {"output": "tel: 612345678"}}`
	if exit := run([]string{"opencode"}, strings.NewReader(read), &stdout, &stderr); exit != 0 {
		t.Fatalf("read exit = %d, stderr = %q, want 0", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "tel: [TEL-001]") {
		t.Fatalf("read output = %s, want the phone as [TEL-001]", stdout.String())
	}

	stdout.Reset()
	edit := `{"event": "tool.execute.before", "sessionID": "ses-1", "tool": "edit", "args": {"filePath": "a.txt", "oldString": "tel: [TEL-001]", "newString": "tel: [TEL-001] (mobile)"}}`
	if exit := run([]string{"opencode"}, strings.NewReader(edit), &stdout, &stderr); exit != 0 {
		t.Fatalf("edit exit = %d, stderr = %q, want 0", exit, stderr.String())
	}
	var out struct {
		Args map[string]string `json:"args"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("edit output %q is not JSON: %v", stdout.String(), err)
	}
	if out.Args["oldString"] != "tel: 612345678" || out.Args["newString"] != "tel: 612345678 (mobile)" {
		t.Errorf("edit args = %v, want the file's own bytes back", out.Args)
	}
}
