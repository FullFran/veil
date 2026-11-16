// Package policy loads veil's declarative policy: which detectors run and
// what veil does with each finding (rewrite or deny). The policy is data,
// validated against a JSON Schema 2020-12 document (policy.schema.json),
// and identified by a content digest. Conditions that need a policy
// language (tenant, purpose, provider) are the host's authority
// (HCS-0005), not veil's.
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/FullFran/veil/internal/problem"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// EnvVar names the environment variable holding the policy file path.
// Unset means the embedded default policy.
const EnvVar = "VEIL_POLICY"

// maxPolicyBytes bounds how much of a policy file veil reads.
const maxPolicyBytes = 1 << 20

//go:embed policy.schema.json
var schemaBytes []byte

//go:embed default.json
var defaultBytes []byte

// Schema returns the published JSON Schema 2020-12 document every policy
// is validated against.
func Schema() []byte { return bytes.Clone(schemaBytes) }

// Action is what veil does with a detector's findings.
type Action string

const (
	// ActionRewrite replaces every match with a stable pseudonym token.
	ActionRewrite Action = "rewrite"
	// ActionDeny blocks the event.
	ActionDeny Action = "deny"
)

// DetectorRule is one detector's entry in the policy.
type DetectorRule struct {
	Action Action `json:"action"`
}

// CatalogRef points at the name catalog file.
type CatalogRef struct {
	Path string `json:"path"`
}

// StoreRules is the pseudonym store's retention.
type StoreRules struct {
	// TTL is an ISO 8601 duration (RFC 3339 Appendix A), for example
	// "P30D": how long a session may sit unused before veil deletes it.
	TTL string `json:"ttl"`
}

// Policy is a validated policy document.
type Policy struct {
	Version   string                  `json:"version"`
	Detectors map[string]DetectorRule `json:"detectors"`
	Catalog   *CatalogRef             `json:"catalog,omitempty"`
	Store     *StoreRules             `json:"store,omitempty"`

	ttl time.Duration

	digest string
	// dir is the directory relative catalog paths resolve against: the
	// policy file's directory, or "" for a policy parsed from bytes.
	dir string
}

// Digest is the policy's content hash: "sha256:" and the hex SHA-256 of
// its RFC 8785 (JCS) canonical form. Whitespace and member order do not
// change it; any change of content does.
func (p *Policy) Digest() string { return p.digest }

var (
	compileOnce sync.Once
	compiled    *jsonschema.Schema
	compileErr  error
)

func schema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
		if err != nil {
			compileErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		const url = "urn:veil:schema:policy:1.0"
		if err := c.AddResource(url, doc); err != nil {
			compileErr = err
			return
		}
		compiled, compileErr = c.Compile(url)
	})
	return compiled, compileErr
}

func invalid(rule, format string, args ...any) error {
	return &Error{Code: problem.PolicyInvalid, Rule: rule, Err: fmt.Errorf(format, args...)}
}

// schemaRule returns the keyword location of the first leaf error the
// schema reported.
func schemaRule(err error) string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return ""
	}
	for _, unit := range ve.BasicOutput().Errors {
		if unit.KeywordLocation != "" {
			return unit.KeywordLocation
		}
	}
	return ""
}

// Parse validates raw as a policy document. Any failure is an *Error with
// problem.PolicyInvalid; a policy is never partially accepted.
func Parse(raw []byte) (*Policy, error) {
	if err := rejectDuplicateKeys(raw); err != nil {
		rule := RuleSyntax
		if errors.Is(err, errDuplicateKey) {
			rule = RuleDuplicateMember
		}
		return nil, invalid(rule, "policy is not one JSON document without duplicate members: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, invalid(RuleSyntax, "policy is not JSON: %w", err)
	}
	s, err := schema()
	if err != nil {
		return nil, fmt.Errorf("veil: compile embedded policy schema: %w", err)
	}
	if err := s.Validate(instance); err != nil {
		return nil, invalid(schemaRule(err), "policy does not match the schema: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalid(RuleSyntax, "decode policy: %w", err)
	}
	if p.Catalog != nil {
		if _, ok := p.Detectors[DetectorNameCatalog]; !ok {
			return nil, invalid(RuleCatalogUnused, "catalog is set but the %s detector is not enabled", DetectorNameCatalog)
		}
	}

	if p.Store != nil {
		ttl, err := parseTTL(p.Store.TTL)
		if err != nil {
			return nil, invalid(RuleTTLNotPositive, "store.ttl: %w", err)
		}
		p.ttl = ttl
	}

	canonical, err := canonicalJSON(instance)
	if err != nil {
		return nil, invalid(RuleSyntax, "canonicalize policy: %w", err)
	}
	sum := sha256.Sum256(canonical)
	p.digest = "sha256:" + hex.EncodeToString(sum[:])
	return &p, nil
}

// Load reads and validates the policy file at path. A read failure is
// problem.PolicyUnreadable; anything else wrong with the file is problem.PolicyInvalid.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &Error{Code: problem.PolicyUnreadable, Err: err}
	}
	defer f.Close()
	raw, err := readLimited(f)
	if err != nil {
		return nil, err
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	p.dir = filepath.Dir(path)
	return p, nil
}

func readLimited(f *os.File) ([]byte, error) {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, &Error{Code: problem.PolicyUnreadable, Err: err}
	}
	if n > maxPolicyBytes {
		return nil, invalid(RuleTooLarge, "policy is larger than %d bytes", maxPolicyBytes)
	}
	return buf.Bytes(), nil
}

// Default returns the policy embedded in the binary: veil's built-in
// behaviour, the same document as default.json.
func Default() *Policy {
	p, err := Parse(defaultBytes)
	if err != nil {
		panic(fmt.Sprintf("veil: embedded default policy is invalid: %v", err))
	}
	return p
}

// FromEnv returns the policy at $VEIL_POLICY, or the default policy when
// it is unset or empty. It never falls back to the default when the
// variable is set: an unreadable or invalid file is an error.
func FromEnv() (*Policy, error) {
	path := os.Getenv(EnvVar)
	if path == "" {
		return Default(), nil
	}
	return Load(path)
}

var errDuplicateKey = errors.New("duplicate object member")

// Retention returns how long a pseudonym session may sit unused before
// veil deletes it, and false when the policy sets no TTL: then veil never
// deletes a session on its own.
func (p *Policy) Retention() (time.Duration, bool) {
	if p.Store == nil {
		return 0, false
	}
	return p.ttl, true
}

// ttlPattern is the schema's pattern for store.ttl, with capture groups.
var ttlPattern = regexp.MustCompile(`^P(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?)?$`)

// parseTTL reads the day/hour/minute subset of an ISO 8601 duration the
// schema accepts. Years and months are excluded: they have no fixed length.
func parseTTL(s string) (time.Duration, error) {
	m := ttlPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("ttl %q is not a day/hour/minute ISO 8601 duration", s)
	}
	var total time.Duration
	for i, unit := range []time.Duration{24 * time.Hour, time.Hour, time.Minute} {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil || n > int64(math.MaxInt64/unit) || total > math.MaxInt64-time.Duration(n)*unit {
			return 0, fmt.Errorf("ttl %q is too large", s)
		}
		total += time.Duration(n) * unit
	}
	if total <= 0 {
		return 0, fmt.Errorf("ttl %q is not positive", s)
	}
	return total, nil
}
