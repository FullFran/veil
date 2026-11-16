package eval_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/FullFran/veil/internal/eval"
	"github.com/FullFran/veil/internal/policy"
)

func TestParseMarkup_RuneOffsets(t *testing.T) {
	plain, spans, err := eval.ParseMarkup("«[[NOMBRE:Lucía Martín]]» — [[DNI:12345678Z]]", "u")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "«Lucía Martín» — 12345678Z" {
		t.Fatalf("plain = %q", plain)
	}
	want := []eval.Span{
		{Unit: "u", Start: 1, End: 13, Label: "NOMBRE"},
		{Unit: "u", Start: 17, End: 26, Label: "DNI"},
	}
	if len(spans) != len(want) || spans[0] != want[0] || spans[1] != want[1] {
		t.Fatalf("spans = %+v, want %+v", spans, want)
	}
}

func TestParseMarkup_Errors(t *testing.T) {
	for _, in := range []string{"[[PASSPORT:X]]", "[[DNI:12345678Z", "[[DNI]]", "[[DNI:]]"} {
		if _, _, err := eval.ParseMarkup(in, ""); !errors.Is(err, eval.ErrMarkup) {
			t.Errorf("ParseMarkup(%q) err = %v, want ErrMarkup", in, err)
		}
	}
}

// TestScore_StrictMatch follows MEDDOCAN sub-track 1: a prediction counts
// only with the same unit, start, end and label.
func TestScore_StrictMatch(t *testing.T) {
	gold := []eval.Span{
		{Unit: "", Start: 0, End: 9, Label: "DNI"},
		{Unit: "", Start: 20, End: 30, Label: "TEL"},
		{Unit: "", Start: 40, End: 50, Label: "EMAIL"},
	}
	pred := []eval.Span{
		{Unit: "", Start: 0, End: 9, Label: "DNI"},    // exact: TP
		{Unit: "", Start: 21, End: 30, Label: "TEL"},  // boundary off: FP + FN
		{Unit: "", Start: 40, End: 50, Label: "IBAN"}, // wrong label: FP(IBAN) + FN(EMAIL)
	}
	var s eval.Scores
	s.Add(gold, pred)

	check := func(label string, tp, fp, fn int) {
		t.Helper()
		c := s.Labels[label]
		if c.TP != tp || c.FP != fp || c.FN != fn {
			t.Errorf("%s = %+v, want tp=%d fp=%d fn=%d", label, c, tp, fp, fn)
		}
	}
	check("DNI", 1, 0, 0)
	check("TEL", 0, 1, 1)
	check("EMAIL", 0, 0, 1)
	check("IBAN", 0, 1, 0)

	micro := s.Micro()
	if micro.TP != 1 || micro.FP != 2 || micro.FN != 2 {
		t.Fatalf("micro = %+v", micro)
	}
	if p, r, f := micro.Precision(), micro.Recall(), micro.F1(); p != 1.0/3 || r != 1.0/3 || f != 1.0/3 {
		t.Fatalf("micro p=%v r=%v f=%v, want 1/3 each", p, r, f)
	}
}

func TestCounts_EmptyIsPerfect(t *testing.T) {
	var c eval.Counts
	if c.Precision() != 1 || c.Recall() != 1 || c.F1() != 1 {
		t.Fatalf("empty counts p=%v r=%v f=%v, want 1", c.Precision(), c.Recall(), c.F1())
	}
}

func TestCheck(t *testing.T) {
	base := eval.Baseline{
		Recall:                map[string]float64{"DNI": 0.9, "TEL": 0.5},
		LatencyP95BudgetMicro: 1000,
	}
	report := func(dniTP, dniFN int, p95 float64) eval.Report {
		return eval.Report{
			Labels:  map[string]eval.Counts{"DNI": {TP: dniTP, FN: dniFN}, "TEL": {TP: 1, FN: 1}},
			Latency: eval.Latency{P95Micro: p95},
		}
	}
	cases := map[string]struct {
		r    eval.Report
		want []eval.Violation
	}{
		"same":           {report(9, 1, 10), nil},
		"better":         {report(10, 0, 10), nil},
		"recall drop":    {report(8, 2, 10), []eval.Violation{{Kind: eval.ViolationRecall, Label: "DNI"}}},
		"latency":        {report(9, 1, 2000), []eval.Violation{{Kind: eval.ViolationLatency}}},
		"label vanished": {eval.Report{Labels: map[string]eval.Counts{"TEL": {TP: 1, FN: 1}}}, []eval.Violation{{Kind: eval.ViolationRecall, Label: "DNI"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := eval.Check(tc.r, base)
			if len(got) != len(tc.want) {
				t.Fatalf("violations = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i].Kind != tc.want[i].Kind || got[i].Label != tc.want[i].Label {
					t.Fatalf("violations = %+v, want %+v", got, tc.want)
				}
			}
		})
	}
}

// TestCorpus_MeetsBaseline is the CI gate: the committed Spanish corpus,
// run with the default policy, must not lower recall on any label below
// the committed baseline nor exceed its p95 latency budget.
func TestCorpus_MeetsBaseline(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "corpus", "es", "v1")
	corpus, err := eval.LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) < 60 {
		t.Fatalf("corpus has %d cases, want at least 60", len(corpus.Cases))
	}
	report, err := eval.Run(corpus, policy.Default(), eval.Options{Repeats: 20})
	if err != nil {
		t.Fatal(err)
	}
	base, err := eval.LoadBaseline(filepath.Join(dir, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range eval.Check(report, base) {
		t.Errorf("baseline violation: %+v", v)
	}
}
