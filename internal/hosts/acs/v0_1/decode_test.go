package v0_1

import (
	"reflect"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestDecodeHook_VendoredExamples decodes every vendored ACS request for
// the hooks in scope into the host-neutral event veil evaluates: its kind,
// tool and session, and among its fields the values a policy must see,
// each named by its JSON pointer under params.
func TestDecodeHook_VendoredExamples(t *testing.T) {
	cases := []struct {
		example string
		kind    domain.EventKind
		session string
		tool    string
		fields  map[string]string
		args    map[string]any
	}{
		{"readme-file-read.request.json", domain.EventToolArgs, "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22", "file_read",
			map[string]string{"/payload/arguments/path/value": "/reports/q3-summary.md", "/payload/tool/name": "file_read", "key /payload/arguments/path": "path"},
			map[string]any{"path": "/reports/q3-summary.md"}},
		{"readme-database-query.request.json", domain.EventToolArgs, "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22", "database_query",
			map[string]string{"/payload/arguments/query/value": "SELECT * FROM customers"},
			map[string]any{"query": "SELECT * FROM customers"}},
		{"in-action-email-send.request.json", domain.EventToolArgs, "7c9e6679-7425-40de-944b-e07fc1f90ae7", "email.send",
			map[string]string{"/payload/arguments/recipient/value": "manager@example.com", "/payload/arguments/body/value": "Project X summary: ..."},
			map[string]any{"recipient": "manager@example.com", "body": "Project X summary: ..."}},
		{"nat-tool-call-request.request.json", domain.EventToolArgs, "00000000-0000-4000-8000-000000000000", "Bash",
			map[string]string{"/payload/arguments/command/value": "echo hello"},
			map[string]any{"command": "echo hello"}},
		{"nat-tool-call-result.request.json", domain.EventToolOutput, "00000000-0000-4000-8000-000000000000", "Bash",
			map[string]string{"/payload/outputs/0/value": "hello\n"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.example, func(t *testing.T) {
			env, ref := decodeEnvelope(readExample(t, tc.example))
			if ref != nil {
				t.Fatalf("decodeEnvelope refused: %+v", ref)
			}
			hook, ref := decodeHook(env)
			if ref != nil {
				t.Fatalf("decodeHook refused: %+v", ref)
			}
			e := hook.event
			if e.Kind != tc.kind || e.Host != domain.HostACS || e.SessionID != tc.session || e.ToolName != tc.tool {
				t.Fatalf("event = %s %s %s %s, want %s acs %s %s", e.Kind, e.Host, e.SessionID, e.ToolName, tc.kind, tc.session, tc.tool)
			}
			for name, want := range tc.fields {
				if e.Fields[name] != want {
					t.Errorf("Fields[%q] = %q, want %q", name, e.Fields[name], want)
				}
			}
			if !reflect.DeepEqual(e.Args, tc.args) {
				t.Errorf("Args = %#v, want %#v", e.Args, tc.args)
			}
			for name, value := range e.Fields {
				if !strings.Contains(e.Text, name+": "+value+"\n") {
					t.Errorf("Text lacks field %s", name)
				}
			}
		})
	}
}
