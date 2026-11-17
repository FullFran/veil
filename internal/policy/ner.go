package policy

import (
	"time"

	"github.com/FullFran/veil/internal/domain"
)

// DetectorNER is the policy id of the NER sidecar detector. Unlike the
// other detectors it is not built by Registry: it needs the model catalog
// and the sidecar's socket, which the caller wires with NER and
// WithAction.
const DetectorNER = "ner"

// Rules for the NER model selection, checked outside the schema.
const (
	RuleNERModelConflict = "veil:ner-model-env-and-policy"
	RuleNERModelIgnored  = "veil:ner-model-env-without-ner"
	RuleNERModelMissing  = "veil:ner-without-model"
)

// NERRule is the resolved ner detector configuration.
type NERRule struct {
	Action Action
	// Model is the catalog id of the selected model.
	Model string
	// Timeout bounds one sidecar exchange; zero means the client default.
	Timeout time.Duration
}

// NER resolves the ner detector: whether the policy enables it and with
// which model. modelEnv is the value of VEIL_NER_MODEL ("" when unset).
// Exactly one of the policy's model and modelEnv must name the model when
// ner is enabled, and modelEnv must be empty when it is not: an ambiguous
// selection is an error, never a silent preference.
func (p *Policy) NER(modelEnv string) (NERRule, bool, error) {
	rule, enabled := p.Detectors[DetectorNER]
	switch {
	case !enabled && modelEnv != "":
		return NERRule{}, false, invalid(RuleNERModelIgnored, "VEIL_NER_MODEL is set but the policy does not enable %s", DetectorNER)
	case !enabled:
		return NERRule{}, false, nil
	case modelEnv != "" && rule.Model != "":
		return NERRule{}, false, invalid(RuleNERModelConflict, "both VEIL_NER_MODEL and the policy's detectors.ner.model are set")
	case modelEnv == "" && rule.Model == "":
		return NERRule{}, false, invalid(RuleNERModelMissing, "the policy enables %s without a model and VEIL_NER_MODEL is unset", DetectorNER)
	}
	model := rule.Model
	if model == "" {
		model = modelEnv
	}
	return NERRule{
		Action:  rule.Action,
		Model:   model,
		Timeout: time.Duration(rule.TimeoutMs) * time.Millisecond, // an integer by the schema
	}, true, nil
}

// WithAction applies action to a detector that can fail: with deny every
// finding loses its Category, so domain.Policy denies instead of
// rewriting, exactly as Registry does for the other detectors.
func WithAction(d domain.FallibleDetector, action Action) domain.FallibleDetector {
	if action != ActionDeny {
		return d
	}
	return denyFallible{d}
}

type denyFallible struct{ inner domain.FallibleDetector }

func (d denyFallible) Name() string { return d.inner.Name() }

func (d denyFallible) Detect(event domain.Event) ([]domain.Finding, error) {
	findings, err := d.inner.Detect(event)
	for i := range findings {
		findings[i].Category = ""
	}
	return findings, err
}
