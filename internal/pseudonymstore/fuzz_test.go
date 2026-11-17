package pseudonymstore

import (
	"bytes"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
)

// Native Go fuzz tests (go test -fuzz) for what the store reads from
// outside: session ids from hosts, session files and key material from
// disk, the keyring or a descriptor.

var stemPattern = regexp.MustCompile(`^[a-z2-7]+(-[a-z2-7]+)?$`)

// nameMax is NAME_MAX on the filesystems veil targets.
const nameMax = 255

// FuzzEncodeStem: every non-empty session id (an empty one fails closed
// with ErrSessionIDMissing before any file is named) gets a stem of the base32 alphabet (and
// "-" when hashed) that fits a file name with its longest suffix, inside
// <dir>/ids, and a plain stem decodes back to the id.
func FuzzEncodeStem(f *testing.F) {
	for _, seed := range []string{"", "s1", "a/b", `a\b`, "a..b", "a_b", "../../etc/passwd", "CON", "unknown-session", strings.Repeat("x", 101), "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if id == "" {
			return
		}
		stem, hashed := encodeStem(id)
		if !stemPattern.MatchString(stem) {
			t.Fatalf("stem of %q = %q, outside the base32 alphabet", id, stem)
		}
		if len(stem+".age.tmp") > nameMax {
			t.Fatalf("stem of %q is %d bytes, too long for a file name", id, len(stem))
		}
		dir := "store"
		if got := SessionPath(dir, id); filepath.Dir(got) != filepath.Join(dir, idsDir) || filepath.Base(got) != stem {
			t.Fatalf("SessionPath(%q) = %q, want %s/%s", id, got, filepath.Join(dir, idsDir), stem)
		}
		if hashed != strings.Contains(stem, "-") {
			t.Fatalf("stem of %q = %q, hashed = %v", id, stem, hashed)
		}
		if hashed {
			return
		}
		decoded, err := stemEncoding.DecodeString(stem)
		if err != nil || string(decoded) != id {
			t.Fatalf("plain stem %q of %q decodes to %q, %v", stem, id, decoded, err)
		}
	})
}

// FuzzEncodeStem_Injective: two distinct session ids never share a stem,
// so they never share a mapping, a counters file or a forget (#26).
func FuzzEncodeStem_Injective(f *testing.F) {
	f.Add("a/b", `a\b`)
	f.Add("a..b", "a_b")
	f.Add("", "unknown-session")
	f.Add(strings.Repeat("x", 100)+"a", strings.Repeat("x", 100)+"b")
	f.Fuzz(func(t *testing.T, a, b string) {
		if a == b {
			return
		}
		stemA, _ := encodeStem(a)
		if stemB, _ := encodeStem(b); stemA == stemB {
			t.Fatalf("session ids %q and %q share the stem %q", a, b, stemA)
		}
	})
}

// fixedKeys is a Keys with one identity.
type fixedKeys struct{ id *age.X25519Identity }

func (k fixedKeys) Identity(bool) (*age.X25519Identity, error) { return k.id, nil }

// encryptTo is plain encrypted to recipient, as a session file.
func encryptTo(f *testing.F, recipient age.Recipient, plain string) []byte {
	f.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := w.Write([]byte(plain)); err != nil {
		f.Fatal(err)
	}
	if err := w.Close(); err != nil {
		f.Fatal(err)
	}
	return buf.Bytes()
}

// FuzzDecrypt: any session file either opens to a version 2 mapping with
// every map present, or fails closed as ErrCorrupt or ErrKeyInvalid.
func FuzzDecrypt(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	for _, plain := range []string{
		`{"version":2,"mapping":{"DNI:12345678Z":"[DNI-001]"},"reverse":{"[DNI-001]":"12345678Z"},"counters":{"DNI":1}}`,
		`{"version":2,"mapping":{},"reverse":{},"written":{"[TEL-001]":"612 345 678"},"counters":{}}`,
		`{"version":1}`,
		`{"version":2,"mapping":null}`,
		`not json`,
	} {
		f.Add(encryptTo(f, id.Recipient(), plain))
	}
	f.Add(encryptTo(f, other.Recipient(), `{"version":2}`))
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Add([]byte{})

	store := NewFileStore(f.TempDir(), fixedKeys{id: id})
	f.Fuzz(func(t *testing.T, raw []byte) {
		data, err := store.decrypt(raw)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrKeyInvalid) {
				t.Fatalf("decrypt(%q) error %v is neither ErrCorrupt nor ErrKeyInvalid", raw, err)
			}
			return
		}
		if data.Version != formatVersion || data.Mapping == nil || data.Reverse == nil || data.Counters == nil {
			t.Fatalf("decrypt(%q) = %+v, want a version %d file with every map", raw, data, formatVersion)
		}
	})
}

// FuzzParseIdentity: any key material is either an X25519 identity or
// ErrKeyInvalid, and the error never quotes a secret key.
func FuzzParseIdentity(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(id.String()))
	f.Add([]byte("# created: 2026-11-17\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"))
	f.Add([]byte(strings.ToLower(id.String())))
	f.Add([]byte("AGE-SECRET-KEY-1"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := parseIdentity(raw)
		if err == nil {
			if got == nil {
				t.Fatalf("parseIdentity(%q) = nil, nil", raw)
			}
			return
		}
		if !errors.Is(err, ErrKeyInvalid) {
			t.Fatalf("parseIdentity(%q) error %v is not ErrKeyInvalid", raw, err)
		}
		if strings.Contains(strings.ToUpper(err.Error()), "AGE-SECRET-KEY-") {
			t.Fatalf("parseIdentity error quotes key material")
		}
	})
}
