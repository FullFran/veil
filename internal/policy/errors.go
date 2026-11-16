package policy

import "github.com/FullFran/veil/internal/problem"

// Error is a policy failure with a stable code: problem.PolicyUnreadable,
// problem.PolicyInvalid or problem.CatalogUnreadable. Callers branch on
// Code (HCS-0006), never on the message.
type Error struct {
	Code problem.Code
	// Rule says which rule an invalid policy broke, for PolicyInvalid: the
	// schema keyword location (a JSON Pointer such as
	// "/properties/version/const") when the schema rejected it, or one of
	// the Rule* constants for the checks veil makes itself. Empty for
	// other codes.
	Rule string
	Err  error
}

// Rules for the checks veil makes outside the schema.
const (
	RuleSyntax          = "veil:json-syntax"
	RuleDuplicateMember = "veil:duplicate-member"
	RuleTooLarge        = "veil:too-large"
	RuleCatalogUnused   = "veil:catalog-without-name-catalog"
	RuleCatalogConflict = "veil:catalog-env-and-path"
	RuleCatalogIgnored  = "veil:catalog-env-without-name-catalog"
)

func (e *Error) Error() string { return string(e.Code) + ": " + e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }
