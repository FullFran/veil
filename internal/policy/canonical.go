package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// canonicalJSON serializes v (as decoded by jsonschema.UnmarshalJSON) in
// the RFC 8785 (JCS) canonical form. The policy schema admits only integer
// numbers (ner.timeoutMs, at most 30000), so numbers are supported when
// they are integers of at most 2^53 in magnitude, where the ECMAScript
// form is the plain decimal integer; any other number is rejected rather
// than guessed at.
func canonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		writeCanonicalString(b, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
			return fmt.Errorf("canonical form of number %s is not supported", x)
		}
		b.WriteString(strconv.FormatInt(int64(f), 10))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// JCS sorts member names by their UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical form of %T is not supported", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeCanonicalString escapes s as RFC 8785 section 3.2.2.2 requires
// (ECMAScript JSON.stringify): only '"', '\\' and control characters are
// escaped, with the short forms where they exist and lowercase \u00xx
// otherwise; everything else is written as UTF-8.
func writeCanonicalString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// rejectDuplicateKeys fails when raw is not exactly one JSON value or when
// any object in it repeats a member name. Most JSON decoders keep the last
// duplicate silently; for a policy that is an implicit choice veil
// refuses to make.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := checkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}

func checkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key := keyTok.(string)
			if seen[key] {
				return fmt.Errorf("%w %q", errDuplicateKey, key)
			}
			seen[key] = true
			if err := checkValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkValue(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}

// RejectDuplicateKeys fails when raw is not exactly one JSON value or
// when any object in it repeats a member name. Other veil documents (the
// NER model catalog) apply the same rule as the policy.
func RejectDuplicateKeys(raw []byte) error { return rejectDuplicateKeys(raw) }
