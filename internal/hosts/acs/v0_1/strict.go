package v0_1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ambiguity kinds: input two JSON parsers can read differently.
const (
	// ambiguityDuplicate is a member name repeated in one object: parsers
	// keep the first, the last or both.
	ambiguityDuplicate = "duplicate member"
	// ambiguityCase is a member name that differs from another in the same
	// object only by case: case-insensitive decoders (encoding/json struct
	// fields among them) merge them, case-sensitive ones do not.
	ambiguityCase = "member differing only by case"
	// ambiguityEncoding is a string with invalid UTF-8 or a lone surrogate
	// escape: parsers reject it or replace it with U+FFFD.
	ambiguityEncoding = "invalid string encoding"
)

// ambiguity is one place in a document where parsers can disagree, by
// kind and the RFC 6901 pointer of the object or string it is in.
type ambiguity struct {
	kind    string
	pointer string
}

// parseJSON parses raw as exactly one JSON value, with numbers as
// json.Number, and reports every ambiguity it holds instead of resolving
// it silently. Malformed JSON or trailing data is an error. Of a repeated
// member, the tree keeps the first value; a caller that finds an
// ambiguity must refuse the document, not read it.
func parseJSON(raw []byte) (any, []ambiguity, error) {
	p := &strictParser{dec: json.NewDecoder(bytes.NewReader(raw)), bad: badStringBytes(raw)}
	p.dec.UseNumber()
	v, err := p.value("")
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("json: unexpected data after the JSON value")
	}
	return v, p.found, nil
}

type strictParser struct {
	dec   *json.Decoder
	bad   []int64 // offsets of invalid bytes or lone surrogates in strings
	found []ambiguity
}

// token reads the next token and reports whether a string token covered a
// bad offset.
func (p *strictParser) token() (json.Token, bool, error) {
	start := p.dec.InputOffset()
	tok, err := p.dec.Token()
	if err != nil {
		return nil, false, err
	}
	if _, ok := tok.(string); !ok {
		return tok, false, nil
	}
	end := p.dec.InputOffset()
	i, _ := slices.BinarySearch(p.bad, start)
	return tok, i < len(p.bad) && p.bad[i] < end, nil
}

func (p *strictParser) value(pointer string) (any, error) {
	tok, bad, err := p.token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if bad {
		p.found = append(p.found, ambiguity{ambiguityEncoding, pointer})
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		folded := map[string]string{}
		for p.dec.More() {
			keyTok, bad, err := p.token()
			if err != nil {
				return nil, fmt.Errorf("json: %w", err)
			}
			key := keyTok.(string)
			if bad {
				p.found = append(p.found, ambiguity{ambiguityEncoding, pointer})
			}
			child := pointer + "/" + escapePointer(key)
			val, err := p.value(child)
			if err != nil {
				return nil, err
			}
			if _, dup := obj[key]; dup {
				p.found = append(p.found, ambiguity{ambiguityDuplicate, pointer})
				continue
			}
			fold := foldKey(key)
			if other, ok := folded[fold]; ok && other != key {
				p.found = append(p.found, ambiguity{ambiguityCase, pointer})
			}
			folded[fold] = key
			obj[key] = val
		}
		if _, err := p.dec.Token(); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		return obj, nil
	case '[':
		arr := []any{}
		for p.dec.More() {
			val, err := p.value(pointer + "/" + strconv.Itoa(len(arr)))
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := p.dec.Token(); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		return arr, nil
	}
	return nil, fmt.Errorf("json: unexpected %v", delim)
}

// foldKey maps every rune of s to the smallest rune of its Unicode simple
// case folding orbit, so two keys fold equal exactly when strings.EqualFold
// holds (the matching encoding/json uses for struct fields).
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}

// badStringBytes returns, in order, the offset of every invalid UTF-8
// byte and every lone surrogate escape (a \uD800-\uDBFF not followed by a
// \uDC00-\uDFFF, or a \uDC00-\uDFFF on its own) inside a JSON string of
// raw. encoding/json replaces both with U+FFFD; RFC 8785 rejects them.
// Bytes outside strings are left to the parser.
func badStringBytes(raw []byte) []int64 {
	var bad []int64
	inString := false
	for i := 0; i < len(raw); {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			i++
			continue
		}
		switch {
		case c == '"':
			inString = false
			i++
		case c == '\\' && i+1 < len(raw) && raw[i+1] == 'u':
			r, ok := hex4(raw, i+2)
			switch {
			case !ok:
				i += 2
			case r >= 0xD800 && r <= 0xDBFF:
				if low, ok := hex4(raw, i+8); ok && i+7 < len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' && low >= 0xDC00 && low <= 0xDFFF {
					i += 12
				} else {
					bad = append(bad, int64(i))
					i += 6
				}
			case r >= 0xDC00 && r <= 0xDFFF:
				bad = append(bad, int64(i))
				i += 6
			default:
				i += 6
			}
		case c == '\\':
			i += 2
		case c < utf8.RuneSelf:
			i++
		default:
			r, size := utf8.DecodeRune(raw[i:])
			if r == utf8.RuneError && size == 1 {
				bad = append(bad, int64(i))
			}
			i += size
		}
	}
	return bad
}

func hex4(raw []byte, at int) (rune, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[at:at+4]), 16, 32)
	return rune(n), err == nil
}
