package policy

import (
	"path/filepath"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/problem"
)

// Detector ids, as used in the policy's detectors object.
const (
	DetectorDNI           = "dni"
	DetectorIBAN          = "iban"
	DetectorEmail         = "email"
	DetectorPhone         = "phone"
	DetectorSecretPath    = "secret-path"
	DetectorBinaryContent = "binary-content"
	DetectorNameCatalog   = "name-catalog"
	DetectorCIF           = "cif"
	DetectorCard          = "card"
	DetectorNSS           = "nss"
	DetectorAddress       = "address"
)

// runOrder is the order veil runs detectors in, whatever order the policy
// file lists them in. It is the order veil used before policies existed,
// which keeps combined deny reasons byte-identical; detectors added
// since run after them.
var runOrder = []string{
	DetectorDNI,
	DetectorIBAN,
	DetectorEmail,
	DetectorPhone,
	DetectorSecretPath,
	DetectorBinaryContent,
	DetectorNameCatalog,
	DetectorCIF,
	DetectorCard,
	DetectorNSS,
	DetectorAddress,
}

// DetectorSet returns the detectors this policy enables, in run order, as
// the raw detectors (actions not applied). catalogEnv is the value of
// VEIL_CATALOG ("" when unset). The evaluation harness uses this to
// measure detection independently of the configured actions.
func (p *Policy) DetectorSet(catalogEnv string) ([]domain.Detector, error) {
	catalogPath, err := p.catalogPath(catalogEnv)
	if err != nil {
		return nil, err
	}
	var detectors []domain.Detector
	for _, id := range runOrder {
		if _, ok := p.Detectors[id]; !ok {
			continue
		}
		switch id {
		case DetectorDNI:
			detectors = append(detectors, domain.NewDNIDetector())
		case DetectorIBAN:
			detectors = append(detectors, domain.NewIBANDetector())
		case DetectorEmail:
			detectors = append(detectors, domain.NewEmailDetector())
		case DetectorPhone:
			detectors = append(detectors, domain.NewPhoneDetector())
		case DetectorSecretPath:
			detectors = append(detectors, domain.NewSecretPathDetector())
		case DetectorBinaryContent:
			detectors = append(detectors, domain.NewBinaryContentDetector())
		case DetectorCIF:
			detectors = append(detectors, domain.NewCIFDetector())
		case DetectorCard:
			detectors = append(detectors, domain.NewCardDetector())
		case DetectorNSS:
			detectors = append(detectors, domain.NewNSSDetector())
		case DetectorAddress:
			detectors = append(detectors, domain.NewAddressDetector())
		case DetectorNameCatalog:
			if catalogPath == "" {
				// No catalog configured: the detector does not run,
				// exactly as with VEIL_CATALOG unset before policies.
				continue
			}
			names, err := domain.LoadNameCatalog(catalogPath)
			if err != nil {
				return nil, &Error{Code: problem.CatalogUnreadable, Err: err}
			}
			detectors = append(detectors, domain.NewNameCatalogDetector(names))
		}
	}
	return detectors, nil
}

// Registry builds the detector registry this policy describes, with each
// detector's action applied: a detector whose action is deny produces
// findings with no Category, which domain.Policy always denies.
func (p *Policy) Registry(catalogEnv string) (*domain.Registry, error) {
	detectors, err := p.DetectorSet(catalogEnv)
	if err != nil {
		return nil, err
	}
	registry := domain.NewRegistry()
	for _, d := range detectors {
		if p.Detectors[d.Name()].Action == ActionDeny {
			d = denyDetector{d}
		}
		registry.Register(d)
	}
	return registry, nil
}

// catalogPath resolves the one catalog source, rejecting ambiguity: both
// VEIL_CATALOG and catalog.path, or a catalog the policy would ignore.
func (p *Policy) catalogPath(catalogEnv string) (string, error) {
	_, enabled := p.Detectors[DetectorNameCatalog]
	switch {
	case catalogEnv != "" && p.Catalog != nil:
		return "", invalid(RuleCatalogConflict, "both VEIL_CATALOG and the policy's catalog.path are set")
	case catalogEnv != "" && !enabled:
		return "", invalid(RuleCatalogIgnored, "VEIL_CATALOG is set but the policy does not enable %s", DetectorNameCatalog)
	case catalogEnv != "":
		return catalogEnv, nil
	case p.Catalog != nil:
		path := filepath.FromSlash(p.Catalog.Path)
		if !filepath.IsAbs(path) && p.dir != "" {
			path = filepath.Join(p.dir, path)
		}
		return path, nil
	default:
		return "", nil
	}
}

// denyDetector applies a deny action: it keeps every finding but drops
// its Category, so domain.Policy denies instead of rewriting.
type denyDetector struct{ inner domain.Detector }

func (d denyDetector) Name() string { return d.inner.Name() }

func (d denyDetector) Detect(event domain.Event) []domain.Finding {
	findings := d.inner.Detect(event)
	for i := range findings {
		findings[i].Category = ""
	}
	return findings
}
