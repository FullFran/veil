package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
)

func wantCode(t *testing.T, err error, code problem.Code) {
	t.Helper()
	var perr *policy.Error
	if !errors.As(err, &perr) {
		t.Fatalf("err = %v, want *policy.Error with code %s", err, code)
	}
	if perr.Code != code {
		t.Fatalf("code = %s, want %s", perr.Code, code)
	}
}

// TestLoad_InvalidFiles runs one invalid file per rule. Each must fail
// with VEIL_POLICY_INVALID, and for the rule the file was written to break.
func TestLoad_InvalidFiles(t *testing.T) {
	const detectors = "/properties/detectors"
	want := map[string]string{
		"unknown-top-level-member.json":            "/additionalProperties",
		"missing-version.json":                     "/required",
		"unsupported-version.json":                 "/properties/version/const",
		"version-not-string.json":                  "/properties/version/const",
		"missing-detectors.json":                   "/required",
		"empty-detectors.json":                     detectors + "/minProperties",
		"unknown-detector.json":                    detectors + "/additionalProperties",
		"bad-action.json":                          detectors + "/properties/dni/$ref/properties/action/enum",
		"missing-action.json":                      detectors + "/properties/dni/$ref/required",
		"unknown-detector-member.json":             detectors + "/properties/dni/$ref/additionalProperties",
		"rewrite-on-deny-only-secret-path.json":    detectors + "/properties/secret-path/$ref/properties/action/const",
		"rewrite-on-deny-only-binary-content.json": detectors + "/properties/binary-content/$ref/properties/action/const",
		"catalog-missing-path.json":                "/properties/catalog/required",
		"catalog-empty-path.json":                  "/properties/catalog/properties/path/minLength",
		"catalog-unknown-member.json":              "/properties/catalog/additionalProperties",
		"catalog-without-name-catalog.json":        policy.RuleCatalogUnused,
		"duplicate-key.json":                       policy.RuleDuplicateMember,
		"trailing-data.json":                       policy.RuleSyntax,
		"not-json.json":                            policy.RuleSyntax,
		"not-an-object.json":                       "/type",
		"store-ttl-not-iso.json":                   "/properties/store/properties/ttl/pattern",
		"store-ttl-months.json":                    "/properties/store/properties/ttl/pattern",
		"store-ttl-zero.json":                      policy.RuleTTLNotPositive,
		"store-missing-ttl.json":                   "/properties/store/required",
		"store-unknown-member.json":                "/properties/store/additionalProperties",
	}
	files, err := filepath.Glob(filepath.Join("testdata", "invalid", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(want) {
		t.Fatalf("found %d invalid fixtures, the table lists %d", len(files), len(want))
	}
	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			rule, ok := want[name]
			if !ok {
				t.Fatalf("no expected rule for %s", name)
			}
			p, err := policy.Load(file)
			if p != nil {
				t.Fatalf("Load returned a policy for an invalid file")
			}
			wantCode(t, err, problem.PolicyInvalid)
			var perr *policy.Error
			errors.As(err, &perr)
			if perr.Rule != rule {
				t.Fatalf("rule = %q, want %q", perr.Rule, rule)
			}
		})
	}
}

func TestLoad_MissingFile_Unreadable(t *testing.T) {
	_, err := policy.Load(filepath.Join(t.TempDir(), "absent.json"))
	wantCode(t, err, problem.PolicyUnreadable)
}

func TestLoad_Valid(t *testing.T) {
	p, err := policy.Load(filepath.Join("testdata", "valid", "minimal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "1.0" {
		t.Fatalf("Version = %q", p.Version)
	}
	if got := p.Detectors["dni"].Action; got != policy.ActionDeny {
		t.Fatalf("dni action = %q, want deny", got)
	}
}

func TestRetention_TTLFromStoreMember(t *testing.T) {
	p, err := policy.Load(filepath.Join("testdata", "valid", "store-ttl.json"))
	if err != nil {
		t.Fatal(err)
	}
	ttl, ok := p.Retention()
	if !ok || ttl != (30*24+12)*time.Hour {
		t.Fatalf("Retention() = (%v, %v), want (732h, true)", ttl, ok)
	}
}

// TestRetention_DefaultKeepsEverything guards the upgrade path: a policy
// without a store member, the default one included, deletes nothing.
func TestRetention_DefaultKeepsEverything(t *testing.T) {
	min, err := policy.Load(filepath.Join("testdata", "valid", "minimal.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*policy.Policy{policy.Default(), min} {
		if ttl, ok := p.Retention(); ok {
			t.Fatalf("Retention() = (%v, true), want no TTL", ttl)
		}
	}
}

func TestDefault_EqualsPublishedDefaultFile(t *testing.T) {
	fromFile, err := policy.Load("default.json")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Default().Digest() != fromFile.Digest() {
		t.Fatalf("embedded default digest %s != default.json digest %s", policy.Default().Digest(), fromFile.Digest())
	}
}

// TestDigest_ChangesOnlyWithContent: whitespace and member order do not
// change the digest; a changed action does.
func TestDigest_ChangesOnlyWithContent(t *testing.T) {
	a, err := policy.Load(filepath.Join("testdata", "valid", "minimal.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Load(filepath.Join("testdata", "valid", "minimal-reordered.json"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("reformatted policy: digest %s != %s", a.Digest(), b.Digest())
	}
	if !strings.HasPrefix(a.Digest(), "sha256:") || len(a.Digest()) != len("sha256:")+64 {
		t.Fatalf("digest %q is not sha256:<64 hex>", a.Digest())
	}

	c, err := policy.Parse([]byte(`{"version":"1.0","detectors":{"dni":{"action":"rewrite"},"email":{"action":"rewrite"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Digest() == a.Digest() {
		t.Fatalf("changed action kept digest %s", a.Digest())
	}
	if policy.Default().Digest() == a.Digest() {
		t.Fatal("default and minimal policies share a digest")
	}
}

func detectorNames(t *testing.T, r *domain.Registry) []string {
	t.Helper()
	var names []string
	for _, d := range r.Detectors() {
		names = append(names, d.Name())
	}
	return names
}

func TestDefault_Registry_IsBuiltInDetectorSet(t *testing.T) {
	r, err := policy.Default().Registry("")
	if err != nil {
		t.Fatal(err)
	}
	want := "dni,iban,email,phone,secret-path,binary-content,cif,card,nss,address"
	if got := strings.Join(detectorNames(t, r), ","); got != want {
		t.Fatalf("detectors = %s, want %s", got, want)
	}

	catalog := writeFile(t, "names.json", `["María Pérez"]`)
	r, err = policy.Default().Registry(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(detectorNames(t, r), ","); got != "dni,iban,email,phone,secret-path,binary-content,name-catalog,cif,card,nss,address" {
		t.Fatalf("detectors with catalog = %s", got)
	}
}

func TestRegistry_FileOrderDoesNotChangeRunOrder(t *testing.T) {
	p, err := policy.Parse([]byte(`{"version":"1.0","detectors":{"secret-path":{"action":"deny"},"email":{"action":"rewrite"},"dni":{"action":"rewrite"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Registry("")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(detectorNames(t, r), ","); got != "dni,email,secret-path" {
		t.Fatalf("detectors = %s", got)
	}
}

func TestRegistry_DenyAction_FindingHasNoCategory(t *testing.T) {
	p, err := policy.Parse([]byte(`{"version":"1.0","detectors":{"dni":{"action":"deny"},"email":{"action":"rewrite"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Registry("")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := r.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: "12345678Z ana@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want 2", findings)
	}
	byDetector := map[string]domain.Finding{}
	for _, f := range findings {
		byDetector[f.Detector] = f
	}
	if byDetector["dni"].Category != "" {
		t.Fatalf("dni finding category = %q, want empty (deny)", byDetector["dni"].Category)
	}
	if byDetector["email"].Category != "EMAIL" {
		t.Fatalf("email finding category = %q, want EMAIL", byDetector["email"].Category)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegistry_CatalogPath_RelativeToPolicyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "names.json"), []byte(`["Juan García"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"version":"1.0","detectors":{"name-catalog":{"action":"rewrite"}},"catalog":{"path":"names.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Registry("")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := r.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: "habla con juan garcia"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Category != "NOMBRE" {
		t.Fatalf("findings = %+v, want one NOMBRE", findings)
	}
}

func TestRegistry_CatalogErrors(t *testing.T) {
	catalog := writeFile(t, "names.json", `["Juan García"]`)
	withPath := func(path string) *policy.Policy {
		dir := t.TempDir()
		file := filepath.Join(dir, "policy.json")
		content := `{"version":"1.0","detectors":{"name-catalog":{"action":"rewrite"}},"catalog":{"path":"` + filepath.ToSlash(path) + `"}}`
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := policy.Load(file)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	noNames, err := policy.Parse([]byte(`{"version":"1.0","detectors":{"dni":{"action":"rewrite"}}}`))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		policy     *policy.Policy
		catalogEnv string
		code       problem.Code
	}{
		"env and path both set":             {withPath(catalog), catalog, problem.PolicyInvalid},
		"env set, name-catalog not enabled": {noNames, catalog, problem.PolicyInvalid},
		"path unreadable":                   {withPath(filepath.Join(t.TempDir(), "absent.json")), "", problem.CatalogUnreadable},
		"env unreadable":                    {policy.Default(), filepath.Join(t.TempDir(), "absent.json"), problem.CatalogUnreadable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := tc.policy.Registry(tc.catalogEnv)
			if r != nil {
				t.Fatal("Registry returned a registry on error")
			}
			wantCode(t, err, tc.code)
		})
	}
}

func TestSchema_Is2020_12(t *testing.T) {
	if !strings.Contains(string(policy.Schema()), `"$schema": "https://json-schema.org/draft/2020-12/schema"`) {
		t.Fatal("schema does not declare the 2020-12 dialect")
	}
}
