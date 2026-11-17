package ner

import (
	"os"

	"github.com/FullFran/veil/internal/policy"
)

// Selection is the NER detector a policy enables: the raw detector, the
// action the policy applies to it and the catalog entry of its model.
type Selection struct {
	Detector *Detector
	Action   policy.Action
	Entry    Entry
}

// FromPolicy resolves the ner detector of p from the environment
// (VEIL_NER_MODEL, VEIL_NER_CATALOG, VEIL_NER_SOCKET). It returns false
// when p does not enable ner.
func FromPolicy(p *policy.Policy) (Selection, bool, error) {
	rule, enabled, err := p.NER(os.Getenv(ModelEnvVar))
	if err != nil || !enabled {
		return Selection{}, false, err
	}
	catalog, err := LoadCatalog(os.Getenv(CatalogEnvVar))
	if err != nil {
		return Selection{}, false, err
	}
	entry, err := catalog.Lookup(rule.Model)
	if err != nil {
		return Selection{}, false, err
	}
	d := NewDetector(Config{
		Socket:  SocketPath(),
		Timeout: rule.Timeout,
		Model:   entry.Model(),
		Labels:  entry.Labels,
	})
	return Selection{Detector: d, Action: rule.Action, Entry: entry}, true, nil
}
