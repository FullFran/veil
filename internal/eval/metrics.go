package eval

import "sort"

// Counts are true positives, false positives and false negatives.
type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
}

// Precision is TP/(TP+FP), or 1 when nothing was predicted.
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}

// Recall is TP/(TP+FN), or 1 when there was nothing to find.
func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

// F1 is the harmonic mean of precision and recall.
func (c Counts) F1() float64 {
	if c.TP+c.FP+c.FN == 0 {
		return 1
	}
	return 2 * float64(c.TP) / float64(2*c.TP+c.FP+c.FN)
}

// Scores accumulates strict span matches per label.
type Scores struct {
	Labels map[string]Counts
}

// Add scores one case: a predicted span is a true positive only if an
// identical gold span (unit, start, end, label) exists.
func (s *Scores) Add(gold, pred []Span) {
	if s.Labels == nil {
		s.Labels = map[string]Counts{}
	}
	goldSet := map[Span]bool{}
	for _, g := range gold {
		goldSet[g] = true
	}
	predSet := map[Span]bool{}
	for _, p := range pred {
		predSet[p] = true
	}
	for p := range predSet {
		c := s.Labels[p.Label]
		if goldSet[p] {
			c.TP++
		} else {
			c.FP++
		}
		s.Labels[p.Label] = c
	}
	for g := range goldSet {
		if !predSet[g] {
			c := s.Labels[g.Label]
			c.FN++
			s.Labels[g.Label] = c
		}
	}
}

// Micro sums the counts of every label (micro-averaging).
func (s *Scores) Micro() Counts {
	var m Counts
	for _, c := range s.Labels {
		m.TP += c.TP
		m.FP += c.FP
		m.FN += c.FN
	}
	return m
}

// percentile returns the nearest-rank p-th percentile of sorted values.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p/100*float64(len(sorted))+0.999999999) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func sortedCopy(v []float64) []float64 {
	out := append([]float64(nil), v...)
	sort.Float64s(out)
	return out
}
