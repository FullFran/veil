package v0_1

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestCanonicalize_MatchesReferenceRFC8785 compares veil's JCS with the
// rfc8785 package the ACS reference adapters use, on an input that
// exercises key order by UTF-16 code unit, ES6 numbers and escaping.
func TestCanonicalize_MatchesReferenceRFC8785(t *testing.T) {
	in := readKAT(t, "jcs-input.json")
	want := readKAT(t, "jcs-canonical.txt")
	got, err := canonicalize(in, "")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonicalize =\n%s\nwant\n%s", got, want)
	}
}

// TestCanonicalize_RFC8785Numbers uses number serializations from RFC 8785
// Appendix B and section 3.2.2.3, as the rfc8785 Python package (the ACS
// reference) renders them.
func TestCanonicalize_RFC8785Numbers(t *testing.T) {
	cases := map[string]string{
		"0":                       "0",
		"-0":                      "0",
		"1E30":                    "1e+30",
		"4.50":                    "4.5",
		"2e-3":                    "0.002",
		"0.000001":                "0.000001",
		"1e-7":                    "1e-7",
		"333333333.33333329":      "333333333.3333333",
		"1e+21":                   "1e+21",
		"9007199254740991":        "9007199254740991",
		"-9007199254740991":       "-9007199254740991",
		"1e300":                   "1e+300",
		"5e-324":                  "5e-324",
		"1.7976931348623157e+308": "1.7976931348623157e+308",
	}
	for in, want := range cases {
		got, err := canonicalize([]byte(in), "")
		if err != nil {
			t.Errorf("canonicalize(%s): %v", in, err)
			continue
		}
		if string(got) != want {
			t.Errorf("canonicalize(%s) = %s, want %s", in, got, want)
		}
	}
}

// TestCanonicalize_RejectsInputWithNoCanonicalForm covers the inputs a
// signature can never cover: duplicate member names (two parsers could
// read different values), integer literals of magnitude 2^53 or more (the
// ACS reference refuses them, so no peer can sign one), invalid UTF-8 and trailing data.
func TestCanonicalize_RejectsInputWithNoCanonicalForm(t *testing.T) {
	cases := map[string]string{
		"duplicate member":         `{"a":1,"a":2}`,
		"nested duplicate member":  `{"p":{"x":"1","x":"1"}}`,
		"integer of 2^53":          `{"n":9007199254740992}`,
		"negative integer of 2^53": `{"n":-9007199254740992}`,
		"integer beyond 2^53":      `{"n":1000000000000000000000}`,
		"invalid utf-8":            "{\"s\":\"\xff\"}",
		"trailing data":            `{} {}`,
		"not json":                 `{`,
	}
	for name, in := range cases {
		if got, err := canonicalize([]byte(in), ""); err == nil {
			t.Errorf("%s: canonicalize = %s, want an error", name, got)
		}
	}
}

// TestCanonicalize_DropsOnlyTheContainerSignature removes the signature
// member of the named container and nothing else.
func TestCanonicalize_DropsOnlyTheContainerSignature(t *testing.T) {
	in := `{"params":{"signature":{"value":"x"},"b":1},"signature":"kept"}`
	got, err := canonicalize([]byte(in), "params")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"params":{"b":1},"signature":"kept"}`; string(got) != want {
		t.Fatalf("canonicalize = %s, want %s", got, want)
	}
}

// TestDeriveKey_SpecificationExample is the known answer in ACS
// Specification section 10: the secret 000102...1f and that session_id.
func TestDeriveKey_SpecificationExample(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	got, err := deriveKey(secret, "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
	if err != nil {
		t.Fatal(err)
	}
	if want := "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4"; hex.EncodeToString(got) != want {
		t.Fatalf("deriveKey = %x, want %s", got, want)
	}
}

func readKAT(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "kat", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
