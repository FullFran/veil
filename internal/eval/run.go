package eval

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/policy"
)

// Options tune a run.
type Options struct {
	// Repeats is how many times each event is evaluated for latency.
	// Zero means 1.
	Repeats int
}

// Latency summarizes domain.Policy.Evaluate time per event, in
// microseconds, over every repeat of every event.
type Latency struct {
	Samples  int     `json:"samples"`
	P50Micro float64 `json:"p50Micros"`
	P95Micro float64 `json:"p95Micros"`
	MaxMicro float64 `json:"maxMicros"`
}

// Report is the result of one run.
type Report struct {
	Corpus  string            `json:"corpus"`
	Policy  string            `json:"policy"`
	Cases   int               `json:"cases"`
	Labels  map[string]Counts `json:"labels"`
	Micro   Counts            `json:"micro"`
	Latency Latency           `json:"latency"`
}

// Run evaluates every case of c under p. Detection is measured with the
// policy's raw detectors (actions do not change what is found); latency
// is measured on the full domain.Policy.Evaluate with actions applied and
// an in-memory pseudonym store. The corpus's own catalog backs the
// name-catalog detector unless the policy names its own.
func Run(c *Corpus, p *policy.Policy, opts Options) (Report, error) {
	catalog := c.CatalogPath
	if p.Catalog != nil {
		catalog = ""
	}
	if _, enabled := p.Detectors[policy.DetectorNameCatalog]; !enabled {
		catalog = ""
	}
	detectors, err := p.DetectorSet(catalog)
	if err != nil {
		return Report{}, err
	}
	registry, err := p.Registry(catalog)
	if err != nil {
		return Report{}, err
	}
	raw := domain.NewRegistry(detectors...)
	evaluator := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	scores := Scores{Labels: map[string]Counts{}}
	for _, label := range Labels {
		scores.Labels[label] = Counts{}
	}
	repeats := opts.Repeats
	if repeats < 1 {
		repeats = 1
	}
	var samples []float64
	for _, cs := range c.Cases {
		scores.Add(cs.Gold, predict(raw.DetectAll(cs.Event), cs.Units))
		for i := 0; i < repeats; i++ {
			start := time.Now()
			if _, err := evaluator.Evaluate(cs.Event); err != nil {
				return Report{}, fmt.Errorf("case %s: %w", cs.ID, err)
			}
			samples = append(samples, float64(time.Since(start).Nanoseconds())/1000)
		}
	}
	sorted := sortedCopy(samples)
	return Report{
		Corpus: c.Dir,
		Policy: p.Digest(),
		Cases:  len(c.Cases),
		Labels: scores.Labels,
		Micro:  scores.Micro(),
		Latency: Latency{
			Samples:  len(sorted),
			P50Micro: percentile(sorted, 50),
			P95Micro: percentile(sorted, 95),
			MaxMicro: percentile(sorted, 100),
		},
	}, nil
}

// predict turns findings into spans: every occurrence of a rewritable
// finding's Match in every unit, which is exactly what domain.Policy
// replaces with a pseudonym token.
func predict(findings []domain.Finding, units map[string]string) []Span {
	var spans []Span
	for _, f := range findings {
		if f.Category == "" || f.Match == "" {
			continue
		}
		for unit, text := range units {
			offset := 0
			for {
				i := strings.Index(text[offset:], f.Match)
				if i < 0 {
					break
				}
				startByte := offset + i
				start := utf8.RuneCountInString(text[:startByte])
				spans = append(spans, Span{Unit: unit, Start: start, End: start + utf8.RuneCountInString(f.Match), Label: f.Category})
				offset = startByte + len(f.Match)
			}
		}
	}
	return spans
}

// Baseline is the committed reference a run must not fall below.
type Baseline struct {
	// Recall is the minimum recall per label.
	Recall map[string]float64 `json:"recall"`
	// LatencyP95BudgetMicro is the maximum p95 Evaluate latency per
	// event, in microseconds. Absolute rather than relative to a
	// measured value, because shared CI runners are noisy.
	LatencyP95BudgetMicro float64 `json:"latencyP95BudgetMicros"`
	// Report is the run the baseline was taken from, for reference.
	Report *Report `json:"report,omitempty"`
}

// ViolationKind classifies a baseline violation.
type ViolationKind string

const (
	ViolationRecall  ViolationKind = "recall"
	ViolationLatency ViolationKind = "latency"
)

// Violation is one way a report falls below its baseline.
type Violation struct {
	Kind     ViolationKind `json:"kind"`
	Label    string        `json:"label,omitempty"`
	Baseline float64       `json:"baseline"`
	Got      float64       `json:"got"`
}

// recallEpsilon absorbs float formatting in the committed baseline.
const recallEpsilon = 1e-9

// Check compares r against b: recall on any baseline label may not drop,
// and p95 latency may not exceed the budget.
func Check(r Report, b Baseline) []Violation {
	labels := make([]string, 0, len(b.Recall))
	for label := range b.Recall {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	var out []Violation
	for _, label := range labels {
		want := b.Recall[label]
		c, ok := r.Labels[label]
		got := 0.0
		if ok {
			got = c.Recall()
		}
		if !ok || got+recallEpsilon < want {
			out = append(out, Violation{Kind: ViolationRecall, Label: label, Baseline: want, Got: got})
		}
	}
	if b.LatencyP95BudgetMicro > 0 && r.Latency.P95Micro > b.LatencyP95BudgetMicro {
		out = append(out, Violation{Kind: ViolationLatency, Baseline: b.LatencyP95BudgetMicro, Got: r.Latency.P95Micro})
	}
	return out
}

// BaselineFrom builds a baseline that pins r's recall per label, with the
// given latency budget.
func BaselineFrom(r Report, latencyBudgetMicro float64) Baseline {
	recall := make(map[string]float64, len(r.Labels))
	for label, c := range r.Labels {
		recall[label] = round4(c.Recall())
	}
	return Baseline{Recall: recall, LatencyP95BudgetMicro: latencyBudgetMicro, Report: &r}
}

// round4 rounds down to 4 decimals, so a pinned recall never exceeds the
// value it was taken from.
func round4(v float64) float64 {
	return float64(int64(v*10000)) / 10000
}
