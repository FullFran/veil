package main

import (
	"fmt"
	"testing"

	"github.com/FullFran/veil/internal/ner"
	"github.com/FullFran/veil/internal/problem"
)

func TestClassifyEvaluateError_NERFailuresHaveTheirOwnCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want problem.Code
	}{
		{ner.ErrUnavailable, problem.NERUnavailable},
		{ner.ErrTimeout, problem.NERTimeout},
		{ner.ErrCrashed, problem.NERCrashed},
		{ner.ErrProtocol, problem.NERProtocol},
		{ner.ErrModelMismatch, problem.NERModelMismatch},
	} {
		// The registry wraps a detector error with the detector's name.
		wrapped := fmt.Errorf("veil: detector ner: %w", fmt.Errorf("%w: detail", tc.err))
		if got := classifyEvaluateError(wrapped); got != tc.want {
			t.Errorf("classifyEvaluateError(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}
