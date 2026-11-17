package v0_1

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxExactInteger is 2^53. The rfc8785 package the ACS reference adapters
// sign with refuses integer literals of this magnitude or more, so no peer
// can produce a signature over one and veil refuses them too.
const maxExactInteger = 1 << 53

// canonicalize returns the RFC 8785 (JCS) canonical form of raw, the input
// ACS signs (Specification section 10). When container is set, the member
// "signature" of the top-level member container (params in a request,
// result in a response) is left out: the signature covers everything but
// itself. Input without a single canonical meaning (duplicate member
// names, invalid UTF-8, lone surrogate escapes, integers beyond 2^53,
// trailing data) is an error.
func canonicalize(raw []byte, container string) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("jcs: invalid UTF-8")
	}
	v, ambiguities, err := parseJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	for _, a := range ambiguities {
		// Case variants have one canonical form (JCS compares names
		// exactly); decodeEnvelope refuses them for veil's own reading.
		if a.kind != ambiguityCase {
			return nil, fmt.Errorf("jcs: %s at %q", a.kind, a.pointer)
		}
	}
	if container != "" {
		if top, ok := v.(map[string]any); ok {
			if inner, ok := top[container].(map[string]any); ok {
				delete(inner, "signature")
			}
		}
	}
	var b strings.Builder
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeValue(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case string:
		writeString(b, t)
	case json.Number:
		s, err := formatNumber(string(t))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeValue(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unexpected value %T", v)
	}
	return nil
}

// compareUTF16 orders member names by their UTF-16 code units (RFC 8785
// section 3.2.3), which differs from byte order above U+FFFF.
func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// formatNumber renders a JSON number as ECMAScript's Number.prototype.
// toString does (RFC 8785 section 3.2.2.3).
func formatNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("jcs: number %s: %w", lit, err)
	}
	if !strings.ContainsAny(lit, ".eE") && math.Abs(f) >= maxExactInteger {
		return "", fmt.Errorf("jcs: integer %s is outside the exact range", lit)
	}
	if f == 0 {
		return "0", nil
	}
	format := byte('f')
	if abs := math.Abs(f); abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	out := strconv.AppendFloat(nil, f, format, -1, 64)
	if format == 'e' {
		// strconv writes e-07 where ECMAScript writes e-7.
		n := len(out)
		if n >= 4 && out[n-4] == 'e' && out[n-3] == '-' && out[n-2] == '0' {
			out[n-2] = out[n-1]
			out = out[:n-1]
		}
	}
	return string(out), nil
}

// writeString escapes only what RFC 8785 section 3.2.2.2 requires: the
// quote, the backslash and control characters, with the short forms where
// JSON has them and lowercase \u00xx otherwise.
func writeString(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
