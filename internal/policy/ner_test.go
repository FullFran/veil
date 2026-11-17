package policy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
)

func mustParse(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse(%s): %v", doc, err)
	}
	return p
}

func TestNER_SelectsTheModel(t *testing.T) {
	cases := map[string]struct {
		doc, env string
		want     policy.NERRule
	}{
		"policy model and timeout": {
			`{"version":"1.0","detectors":{"ner":{"action":"rewrite","model":"gliner2-pii","timeoutMs":1500}}}`, "",
			policy.NERRule{Action: policy.ActionRewrite, Model: "gliner2-pii", Timeout: 1500 * time.Millisecond},
		},
		"env model, default timeout": {
			`{"version":"1.0","detectors":{"ner":{"action":"deny"}}}`, "spacy-es-core-news-lg",
			policy.NERRule{Action: policy.ActionDeny, Model: "spacy-es-core-news-lg"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok, err := mustParse(t, tc.doc).NER(tc.env)
			if err != nil || !ok {
				t.Fatalf("NER = %+v, %v, %v; want enabled", got, ok, err)
			}
			if got != tc.want {
				t.Fatalf("NER = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestNER_OffUnlessThePolicyEnablesIt(t *testing.T) {
	if _, ok, err := policy.Default().NER(""); ok || err != nil {
		t.Fatalf("default policy: enabled %v, err %v; want off", ok, err)
	}
}

func TestNER_AmbiguousSelectionIsInvalid(t *testing.T) {
	withModel := `{"version":"1.0","detectors":{"ner":{"action":"rewrite","model":"gliner2-pii"}}}`
	noModel := `{"version":"1.0","detectors":{"ner":{"action":"rewrite"}}}`
	noNER := `{"version":"1.0","detectors":{"dni":{"action":"rewrite"}}}`
	cases := map[string]struct {
		doc, env, rule string
	}{
		"env and model both set":   {withModel, "spacy-es-core-news-lg", policy.RuleNERModelConflict},
		"env set, ner not enabled": {noNER, "gliner2-pii", policy.RuleNERModelIgnored},
		"enabled, no model at all": {noModel, "", policy.RuleNERModelMissing},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := mustParse(t, tc.doc).NER(tc.env)
			wantCode(t, err, problem.PolicyInvalid)
			var perr *policy.Error
			if errors.As(err, &perr); perr.Rule != tc.rule {
				t.Fatalf("rule = %q, want %q", perr.Rule, tc.rule)
			}
		})
	}
}

func TestNER_SchemaBoundsTheEntry(t *testing.T) {
	for name, ner := range map[string]string{
		"timeout zero":     `{"action":"rewrite","timeoutMs":0}`,
		"timeout too long": `{"action":"rewrite","timeoutMs":30001}`,
		"timeout fraction": `{"action":"rewrite","timeoutMs":1.5}`,
		"empty model":      `{"action":"rewrite","model":""}`,
		"unknown member":   `{"action":"rewrite","labels":["person"]}`,
		"unknown action":   `{"action":"allow"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := policy.Parse([]byte(`{"version":"1.0","detectors":{"ner":` + ner + `}}`))
			wantCode(t, err, problem.PolicyInvalid)
		})
	}
}

func TestNER_DigestCoversTheTimeoutValue(t *testing.T) {
	doc := func(timeout string) string {
		return `{"version":"1.0","detectors":{"ner":{"action":"rewrite","model":"m","timeoutMs":` + timeout + `}}}`
	}
	a, b, c := mustParse(t, doc("1500")), mustParse(t, doc("1.5e3")), mustParse(t, doc("2000"))
	if a.Digest() != b.Digest() {
		t.Fatal("1500 and 1.5e3 are the same number but have different digests")
	}
	if a.Digest() == c.Digest() {
		t.Fatal("changing timeoutMs kept the digest")
	}
}

type fallibleNames struct{}

func (fallibleNames) Name() string { return "ner" }

func (fallibleNames) Detect(domain.Event) ([]domain.Finding, error) {
	return []domain.Finding{{Detector: "ner", Match: "Ana", Redacted: "[NOMBRE]", Category: "NOMBRE"}}, nil
}

func TestWithAction_DenyDropsTheCategory(t *testing.T) {
	for action, category := range map[policy.Action]string{policy.ActionRewrite: "NOMBRE", policy.ActionDeny: ""} {
		findings, err := policy.WithAction(fallibleNames{}, action).Detect(domain.Event{})
		if err != nil || len(findings) != 1 || findings[0].Category != category {
			t.Fatalf("%s: findings %+v, err %v; want category %q", action, findings, err, category)
		}
	}
}
