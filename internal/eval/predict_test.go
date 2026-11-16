package eval

import (
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// TestPredict_LongestMatchWins proves predict scores what domain.Policy
// replaces: a match inside a longer one is not a span of its own.
func TestPredict_LongestMatchWins(t *testing.T) {
	findings := []domain.Finding{
		{Match: "Juan García", Category: "NOMBRE"},
		{Match: "Juan García-López", Category: "NOMBRE"},
	}
	got := predict(findings, map[string]string{"prompt": "Juan García y Juan García-López"})
	want := []Span{
		{Unit: "prompt", Start: 0, End: 11, Label: "NOMBRE"},
		{Unit: "prompt", Start: 14, End: 31, Label: "NOMBRE"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d spans, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("span %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
