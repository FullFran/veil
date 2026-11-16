package v0_1

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaFS holds the ACS v0.1.0 JSON Schemas exactly as published at the
// commit pinned in spec/SOURCE.md; spec/SHA256SUMS pins their bytes.
//
//go:embed spec/schema
var schemaFS embed.FS

// schemaBase is the $id prefix every vendored schema declares, so the
// relative $refs between them resolve without any network access.
const schemaBase = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/"

// The schemas veil validates against, by location.
const (
	schemaRequest     = schemaBase + "request-envelope.json"
	schemaResponse    = schemaBase + "response-envelope.json"
	schemaClientHello = schemaBase + "handshake.json#/$defs/ClientHello"
	schemaToolRequest = schemaBase + "hooks/tool-call-request.json"
	schemaToolResult  = schemaBase + "hooks/tool-call-result.json"
	schemaPing        = schemaBase + "hooks/system-ping.json"
)

var (
	schemasOnce sync.Once
	schemas     map[string]*jsonschema.Schema
	schemasErr  error
)

// compiled returns the vendored schemas, compiled once with format
// assertions on (uuid, date-time), so a malformed request_id or timestamp
// is a schema divergence, not a value veil has to second-guess.
func compiled() (map[string]*jsonschema.Schema, error) {
	schemasOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		err := fs.WalkDir(schemaFS, "spec/schema", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			raw, err := schemaFS.ReadFile(path)
			if err != nil {
				return err
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			return c.AddResource(schemaBase+path[len("spec/schema/"):], doc)
		})
		if err != nil {
			schemasErr = err
			return
		}
		schemas = map[string]*jsonschema.Schema{}
		for _, loc := range []string{schemaRequest, schemaResponse, schemaClientHello, schemaToolRequest, schemaToolResult, schemaPing} {
			s, err := c.Compile(loc)
			if err != nil {
				schemasErr = fmt.Errorf("compile %s: %w", loc, err)
				return
			}
			schemas[loc] = s
		}
	})
	return schemas, schemasErr
}

// validate checks v (a value from jsonschema.UnmarshalJSON) against the
// schema at loc.
func validate(loc string, v any) error {
	s, err := compiled()
	if err != nil {
		return err
	}
	return s[loc].Validate(v)
}

// validateResponse checks a whole response body against the response
// envelope schema, the shape every answer veil writes must have.
func validateResponse(raw []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return validate(schemaResponse, v)
}
