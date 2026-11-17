package eval_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/eval"
	"github.com/FullFran/veil/internal/policy"
)

// everyText reports each event's whole text as one NOMBRE finding and
// counts its calls.
type everyText struct {
	calls *int
	err   error
}

func (everyText) Name() string { return "ner" }

func (d everyText) Detect(e domain.Event) ([]domain.Finding, error) {
	*d.calls++
	if d.err != nil || e.Text == "" {
		return nil, d.err
	}
	return []domain.Finding{{Detector: "ner", Match: e.Text, Redacted: "[NOMBRE]", Category: "NOMBRE"}}, nil
}

func loadCorpus(t *testing.T) *eval.Corpus {
	t.Helper()
	c, err := eval.LoadCorpus(filepath.Join("..", "..", "testdata", "corpus", "es", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRun_NERDetectorIsMeasured(t *testing.T) {
	corpus := loadCorpus(t)
	p, err := policy.Parse([]byte(`{"version":"1.0","detectors":{"ner":{"action":"rewrite","model":"m"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	report, err := eval.Run(corpus, p, eval.Options{Repeats: 1, NER: everyText{calls: &calls}, NERAction: policy.ActionRewrite})
	if err != nil {
		t.Fatal(err)
	}
	if calls < 2*len(corpus.Cases) {
		t.Fatalf("calls = %d, want the detector run for detection and for latency on %d cases", calls, len(corpus.Cases))
	}
	if n := report.Labels["NOMBRE"]; n.TP+n.FP == 0 {
		t.Fatalf("NOMBRE = %+v, want the NER findings scored", n)
	}
}

func TestRun_NERFailureFailsTheRun(t *testing.T) {
	stub := errors.New("sidecar down")
	calls := 0
	_, err := eval.Run(loadCorpus(t), policy.Default(), eval.Options{Repeats: 1, NER: everyText{calls: &calls, err: stub}})
	if !errors.Is(err, stub) {
		t.Fatalf("err = %v, want the detector's error", err)
	}
}
