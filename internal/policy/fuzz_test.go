package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/FullFran/veil/internal/policy"
	"github.com/FullFran/veil/internal/problem"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// FuzzParse (go test -fuzz): any policy document is either accepted with a
// SHA-256 digest that is the same on every parse, or refused with a
// *policy.Error of code VEIL_POLICY_INVALID; Parse never panics.
func FuzzParse(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*", "*.json"))
	if err != nil {
		f.Fatal(err)
	}
	paths = append(paths, "default.json")
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- fixed test fixtures inside the repository
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := policy.Parse(raw)
		if err != nil {
			var perr *policy.Error
			if !errors.As(err, &perr) || perr.Code != problem.PolicyInvalid {
				t.Fatalf("Parse(%q) error %v is not a %s *policy.Error", raw, err, problem.PolicyInvalid)
			}
			return
		}
		if !digestPattern.MatchString(p.Digest()) {
			t.Fatalf("Parse(%q) digest = %q", raw, p.Digest())
		}
		again, err := policy.Parse(raw)
		if err != nil || again.Digest() != p.Digest() {
			t.Fatalf("Parse(%q) is not deterministic: %v, %q vs %q", raw, err, again.Digest(), p.Digest())
		}
	})
}
