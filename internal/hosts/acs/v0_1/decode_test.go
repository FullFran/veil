package v0_1

import (
	"reflect"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestDecodeHook_VendoredExamples decodes every vendored ACS request for
// the hooks in scope into the host-neutral event veil evaluates.
func TestDecodeHook_VendoredExamples(t *testing.T) {
	cases := []struct {
		example string
		want    domain.Event
	}{
		{
			example: "readme-file-read.request.json",
			want: domain.Event{
				Kind:      domain.EventToolArgs,
				Host:      domain.HostACS,
				SessionID: "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22",
				ToolName:  "file_read",
				Text:      "path: /reports/q3-summary.md\n",
				Fields:    map[string]string{"path": "/reports/q3-summary.md"},
				Args:      map[string]any{"path": "/reports/q3-summary.md"},
			},
		},
		{
			example: "readme-database-query.request.json",
			want: domain.Event{
				Kind:      domain.EventToolArgs,
				Host:      domain.HostACS,
				SessionID: "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22",
				ToolName:  "database_query",
				Text:      "query: SELECT * FROM customers\n",
				Fields:    map[string]string{"query": "SELECT * FROM customers"},
				Args:      map[string]any{"query": "SELECT * FROM customers"},
			},
		},
		{
			example: "in-action-email-send.request.json",
			want: domain.Event{
				Kind:      domain.EventToolArgs,
				Host:      domain.HostACS,
				SessionID: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
				ToolName:  "email.send",
				Text:      "body: Project X summary: ...\nrecipient: manager@example.com\n",
				Fields: map[string]string{
					"recipient": "manager@example.com",
					"body":      "Project X summary: ...",
				},
				Args: map[string]any{
					"recipient": "manager@example.com",
					"body":      "Project X summary: ...",
				},
			},
		},
		{
			example: "nat-tool-call-request.request.json",
			want: domain.Event{
				Kind:      domain.EventToolArgs,
				Host:      domain.HostACS,
				SessionID: "00000000-0000-4000-8000-000000000000",
				ToolName:  "Bash",
				Text:      "command: echo hello\n",
				Fields:    map[string]string{"command": "echo hello"},
				Args:      map[string]any{"command": "echo hello"},
			},
		},
		{
			example: "nat-tool-call-result.request.json",
			want: domain.Event{
				Kind:      domain.EventToolOutput,
				Host:      domain.HostACS,
				SessionID: "00000000-0000-4000-8000-000000000000",
				ToolName:  "Bash",
				Text:      "outputs.0: hello\n\n",
				Fields:    map[string]string{"outputs.0": "hello\n"},
			},
		},
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
			if !reflect.DeepEqual(hook.event, tc.want) {
				t.Fatalf("event =\n%#v\nwant\n%#v", hook.event, tc.want)
			}
		})
	}
}
