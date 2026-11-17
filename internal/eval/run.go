package eval

import (
	"fmt"
	"regexp"
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
	// NER, when set, is the policy's ner detector (veil-eval wires it
	// from the environment like veil does); NERAction is its action.
	NER       domain.FallibleDetector
	NERAction policy.Action
}

// Latency summarizes domain.Policy.Evaluate time per event, in
// microseconds, over every repeat of every event, and its cost relative
// to a calibration workload timed in the same process.
//
// The absolute figures depend on the machine and on its load, so they
// are reported, never gated. Ratio is what the baseline gates: each
// Evaluate sample is paired with a calibration sample taken right before
// it on the same event, so load that slows one slows the other.
type Latency struct {
	Samples  int     `json:"samples"`
	P50Micro float64 `json:"p50Micros"`
	P95Micro float64 `json:"p95Micros"`
	MaxMicro float64 `json:"maxMicros"`
	// CalibrationP50Micro is the median time of the calibration workload
	// per event.
	CalibrationP50Micro float64 `json:"calibrationP50Micros"`
	// Ratio is the sum over events of the median Evaluate time divided by
	// the sum over events of the median calibration time.
	Ratio float64 `json:"ratio"`
}

// calibration is the reference workload Evaluate is timed against: a
// standard-library regular expression scanned over every unit of the
// event. It is pure Go, like veil's detectors, so the race detector and
// CPU contention slow it in a similar proportion, and it does not depend
// on any veil code, so a veil regression does not move it.
var calibration = regexp.MustCompile(`[\p{L}0-9._%+-]+@[\p{L}0-9.-]+|\b[0-9]{8}[A-Z]\b|\b[6-9][0-9 ]{8,11}\b`)

// calibrationPasses scales the calibration workload so that one sample
// lasts about as long as one Evaluate, which keeps timer resolution out
// of the ratio.
const calibrationPasses = 4

// slowdown multiplies the work timed as one Evaluate sample. It is 1 in
// production; tests raise it through export_test.go to prove the gate
// catches an order-of-magnitude regression.
var slowdown = 1

func calibrate(units map[string]string) int {
	n := 0
	for i := 0; i < calibrationPasses; i++ {
		for _, text := range units {
			n += len(calibration.FindAllStringIndex(text, -1))
		}
	}
	return n
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
	if opts.NER != nil {
		raw.RegisterFallible(opts.NER)
		registry.RegisterFallible(policy.WithAction(opts.NER, opts.NERAction))
	}
	evaluator := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	scores := Scores{Labels: map[string]Counts{}}
	for _, label := range Labels {
		scores.Labels[label] = Counts{}
	}
	repeats := opts.Repeats
	if repeats < 1 {
		repeats = 1
	}
	var samples, calSamples []float64
	var evalSum, calSum float64
	for _, cs := range c.Cases {
		found, err := raw.DetectAll(cs.Event)
		if err != nil {
			return Report{}, fmt.Errorf("case %s: %w", cs.ID, err)
		}
		scores.Add(cs.Gold, predict(found, cs.Units))
		evalCase := make([]float64, 0, repeats)
		calCase := make([]float64, 0, repeats)
		for i := 0; i < repeats; i++ {
			start := time.Now()
			calibrate(cs.Units)
			calCase = append(calCase, micros(time.Since(start)))
			start = time.Now()
			for k := 0; k < slowdown; k++ {
				if _, err := evaluator.Evaluate(cs.Event); err != nil {
					return Report{}, fmt.Errorf("case %s: %w", cs.ID, err)
				}
			}
			evalCase = append(evalCase, micros(time.Since(start)))
		}
		evalSum += percentile(sortedCopy(evalCase), 50)
		calSum += percentile(sortedCopy(calCase), 50)
		samples = append(samples, evalCase...)
		calSamples = append(calSamples, calCase...)
	}
	ratio := 0.0
	if calSum > 0 {
		ratio = evalSum / calSum
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

			CalibrationP50Micro: percentile(sortedCopy(calSamples), 50),
			Ratio:               ratio,
		},
	}, nil
}

func micros(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1000
}

// predict turns findings into spans: exactly what domain.Policy replaces
// with a pseudonym token. Like its substitution, the scan is one
// left-to-right pass over each unit that prefers the longest match at
// each position, so a match inside a longer one ("Juan García" inside
// "Juan García-López") is not counted on its own.
func predict(findings []domain.Finding, units map[string]string) []Span {
	label := map[string]string{}
	var matches []string
	for _, f := range findings {
		if f.Category == "" || f.Match == "" {
			continue
		}
		if _, seen := label[f.Match]; !seen {
			label[f.Match] = f.Category
			matches = append(matches, f.Match)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i]) != len(matches[j]) {
			return len(matches[i]) > len(matches[j])
		}
		return matches[i] < matches[j]
	})
	var spans []Span
	for unit, text := range units {
		for i := 0; i < len(text); {
			match := longestAt(text[i:], matches)
			if match == "" {
				i++
				continue
			}
			start := utf8.RuneCountInString(text[:i])
			spans = append(spans, Span{Unit: unit, Start: start, End: start + utf8.RuneCountInString(match), Label: label[match]})
			i += len(match)
		}
	}
	return spans
}

// longestAt returns the first of matches (sorted longest first) that s
// starts with, or "".
func longestAt(s string, matches []string) string {
	for _, m := range matches {
		if strings.HasPrefix(s, m) {
			return m
		}
	}
	return ""
}

// Baseline is the committed reference a run must not fall below.
type Baseline struct {
	// Recall is the minimum recall per label.
	Recall map[string]float64 `json:"recall"`
	// LatencyRatioBudget is the maximum Latency.Ratio: Evaluate cost
	// relative to the in-process calibration workload. A ratio, not
	// microseconds, so machine load and the race detector, which slow
	// both sides alike, do not fail the gate; an order-of-magnitude
	// regression in Evaluate does.
	LatencyRatioBudget float64 `json:"latencyRatioBudget"`
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
// and the latency ratio may not exceed the budget. Absolute latency is
// never checked.
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
	if b.LatencyRatioBudget > 0 && r.Latency.Ratio > b.LatencyRatioBudget {
		out = append(out, Violation{Kind: ViolationLatency, Baseline: b.LatencyRatioBudget, Got: r.Latency.Ratio})
	}
	return out
}

// DefaultLatencyRatioHeadroom is how far above a measured ratio a new
// baseline's budget is set when none is given: wide enough for noise
// and for differences between CI machines, narrow enough that a tenfold
// regression fails.
const DefaultLatencyRatioHeadroom = 3

// BaselineFrom builds a baseline that pins r's recall per label, with the
// given latency ratio budget.
func BaselineFrom(r Report, latencyRatioBudget float64) Baseline {
	recall := make(map[string]float64, len(r.Labels))
	for label, c := range r.Labels {
		recall[label] = round4(c.Recall())
	}
	return Baseline{Recall: recall, LatencyRatioBudget: latencyRatioBudget, Report: &r}
}

// round4 rounds down to 4 decimals, so a pinned recall never exceeds the
// value it was taken from.
func round4(v float64) float64 {
	return float64(int64(v*10000)) / 10000
}
