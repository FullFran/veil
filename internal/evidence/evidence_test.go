package evidence_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/evidence"
)

var fixedTime = time.Date(2026, 11, 16, 10, 30, 0, 0, time.UTC)

func baseInput() evidence.Input {
	return evidence.Input{
		ID:            "0b6c1f5e-7d0e-4c55-9a3e-5f3a3a1b2c3d",
		Time:          fixedTime,
		Host:          domain.HostOpenCode,
		Event:         domain.EventToolArgs,
		Tool:          "bash",
		Session:       "sess-1",
		Action:        domain.Allow,
		PolicyDigest:  "sha256:abc",
		PolicyVersion: "1.0",
		Duration:      3 * time.Millisecond,
	}
}

// decode builds in and returns the record as generic JSON, the way a
// consumer that knows nothing about veil's Go types would see it.
func decode(t *testing.T, in evidence.Input) map[string]any {
	t.Helper()
	rec, err := evidence.Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return m
}

func obj(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("member %q = %#v, want an object", key, m[key])
	}
	return v
}

func num(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("member %q = %#v, want a number", key, m[key])
	}
	return int(v)
}

// TestBuild_CloudEventsEnvelope checks the CloudEvents 1.0.2 required
// context attributes and the optional ones veil always sets.
func TestBuild_CloudEventsEnvelope(t *testing.T) {
	m := decode(t, baseInput())

	want := map[string]string{
		"specversion":     "1.0",
		"id":              "0b6c1f5e-7d0e-4c55-9a3e-5f3a3a1b2c3d",
		"source":          evidence.Source,
		"type":            evidence.Type,
		"time":            "2026-11-16T10:30:00Z",
		"datacontenttype": "application/json",
		"dataschema":      evidence.DataSchema,
	}
	for key, value := range want {
		if m[key] != value {
			t.Errorf("%s = %#v, want %q", key, m[key], value)
		}
	}
	obj(t, m, "data")
	for key := range m {
		if _, known := want[key]; !known && key != "data" {
			t.Errorf("unexpected envelope member %q", key)
		}
	}
}

// TestBuild_OCSFDataSecurityFinding checks the members OCSF 1.9.0 marks
// required for class 2006 and the action mapping per decision kind.
func TestBuild_OCSFDataSecurityFinding(t *testing.T) {
	cases := []struct {
		action      domain.DecisionKind
		actionID    int
		disposition int
		severity    int
	}{
		{domain.Allow, 1, 1, 1},
		{domain.Deny, 2, 2, 3},
		{domain.Rewrite, 4, 99, 2},
	}
	for _, c := range cases {
		t.Run(c.action.String(), func(t *testing.T) {
			in := baseInput()
			in.Action = c.action
			data := obj(t, decode(t, in), "data")

			for key, want := range map[string]int{
				"category_uid":   2,
				"class_uid":      2006,
				"activity_id":    1,
				"type_uid":       200601,
				"severity_id":    c.severity,
				"action_id":      c.actionID,
				"disposition_id": c.disposition,
				"time":           int(fixedTime.UnixMilli()),
				"duration":       3,
			} {
				if got := num(t, data, key); got != want {
					t.Errorf("%s = %d, want %d", key, got, want)
				}
			}

			meta := obj(t, data, "metadata")
			if meta["version"] != evidence.OCSFVersion {
				t.Errorf("metadata.version = %#v, want %q", meta["version"], evidence.OCSFVersion)
			}
			if meta["uid"] != in.ID {
				t.Errorf("metadata.uid = %#v, want the record id", meta["uid"])
			}
			if obj(t, meta, "product")["name"] != "veil" {
				t.Errorf("metadata.product.name is not veil")
			}
			if obj(t, data, "finding_info")["uid"] != in.ID {
				t.Errorf("finding_info.uid is not the record id")
			}

			actor := obj(t, data, "actor")
			if actor["app_name"] != "opencode" {
				t.Errorf("actor.app_name = %#v, want opencode", actor["app_name"])
			}
			if obj(t, actor, "session")["uid"] != "sess-1" {
				t.Errorf("actor.session.uid is not the session id")
			}

			policy := obj(t, obj(t, data, "data_security"), "policy")
			if policy["uid"] != "sha256:abc" || policy["version"] != "1.0" {
				t.Errorf("data_security.policy = %#v, want the digest and version", policy)
			}

			veil := obj(t, obj(t, data, "unmapped"), "veil")
			if veil["event"] != "ToolArgs" || veil["tool"] != "bash" {
				t.Errorf("unmapped.veil = %#v, want event and tool", veil)
			}
			if _, present := veil["catalog_revision"]; present {
				t.Errorf("unmapped.veil.catalog_revision present without a revision")
			}
		})
	}
}

// TestBuild_UnknownActionFails: a zero-valued decision is never recorded
// as if it were a verdict.
func TestBuild_UnknownActionFails(t *testing.T) {
	in := baseInput()
	in.Action = domain.Unknown
	if _, err := evidence.Build(in); err == nil {
		t.Fatal("Build with an unknown action succeeded, want an error")
	}
}

func TestBuild_CatalogRevision(t *testing.T) {
	in := baseInput()
	in.CatalogRevision = "clients-2026-11:r7"
	veil := obj(t, obj(t, decode(t, in), "data"), "unmapped")["veil"].(map[string]any)
	if veil["catalog_revision"] != "clients-2026-11:r7" {
		t.Fatalf("catalog_revision = %#v, want the host revision as-is", veil["catalog_revision"])
	}
}

// TestBuild_DiscoveryDetails maps findings to DPV PD IRIs by detector id
// (a deny action strips the category, the detector id stays) and counts
// them, never carrying a value.
func TestBuild_DiscoveryDetails(t *testing.T) {
	in := baseInput()
	in.Action = domain.Deny
	in.Findings = []domain.Finding{
		{Detector: "dni", Category: "DNI", Match: "12345678Z"},
		{Detector: "dni", Category: "", Match: "X1234567L"},
		{Detector: "email", Category: "EMAIL", Match: "ana@example.com"},
		{Detector: "name-catalog", Category: "NOMBRE", Match: "María Pérez"},
		{Detector: "phone", Category: "TEL", Match: "600123456"},
		{Detector: "iban", Category: "IBAN", Match: "ES9121000418450200051332"},
		{Detector: "secret-path", Match: "/repo/.env"},
	}
	ds := obj(t, obj(t, decode(t, in), "data"), "data_security")

	details, ok := ds["discovery_details"].([]any)
	if !ok {
		t.Fatalf("discovery_details = %#v, want an array", ds["discovery_details"])
	}
	type entry struct {
		Type  string
		Count int
		Rule  string
	}
	var got []entry
	for _, d := range details {
		m := d.(map[string]any)
		if _, present := m["value"]; present {
			t.Errorf("discovery_details entry carries a value: %#v", m)
		}
		got = append(got, entry{m["type"].(string), int(m["count"].(float64)), m["rule"].(map[string]any)["uid"].(string)})
	}
	want := []entry{
		{"https://w3id.org/dpv/pd#OfficialID", 2, "dni"},
		{"https://w3id.org/dpv/pd#EmailAddress", 1, "email"},
		{"https://w3id.org/dpv/pd#FinancialAccountNumber", 1, "iban"},
		{"https://w3id.org/dpv/pd#Name", 1, "name-catalog"},
		{"https://w3id.org/dpv/pd#TelephoneNumber", 1, "phone"},
		{"secret-path", 1, "secret-path"},
	}
	if len(got) != len(want) {
		t.Fatalf("discovery_details = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("discovery_details[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if num(t, ds, "category_id") != 1 {
		t.Errorf("category_id = %v, want 1 (Personal) when personal data was found", ds["category_id"])
	}
}

func TestBuild_SecurityOnlyCategory(t *testing.T) {
	in := baseInput()
	in.Action = domain.Deny
	in.Findings = []domain.Finding{{Detector: "binary-content"}}
	ds := obj(t, obj(t, decode(t, in), "data"), "data_security")
	if num(t, ds, "category_id") != 6 {
		t.Errorf("category_id = %v, want 6 (Security) for a non-personal finding", ds["category_id"])
	}
}

func TestBuild_NoFindings_NoDiscoveryDetails(t *testing.T) {
	ds := obj(t, obj(t, decode(t, baseInput()), "data"), "data_security")
	if _, present := ds["discovery_details"]; present {
		t.Errorf("discovery_details present on a clean allow")
	}
	if _, present := ds["category_id"]; present {
		t.Errorf("category_id present on a clean allow")
	}
}

func TestValidateRevision(t *testing.T) {
	for _, ok := range []string{"r1", "clients-2026-11:r7", "a.b_c", strings.Repeat("x", 128)} {
		if err := evidence.ValidateRevision(ok); err != nil {
			t.Errorf("ValidateRevision(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "has space", "María", strings.Repeat("x", 129), "a/b", "x\n"} {
		if err := evidence.ValidateRevision(bad); !errors.Is(err, evidence.ErrRevisionInvalid) {
			t.Errorf("ValidateRevision(%q) = %v, want ErrRevisionInvalid", bad, err)
		}
	}
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewID_IsUUIDv4(t *testing.T) {
	a, err := evidence.NewID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := evidence.NewID()
	if !uuidV4.MatchString(a) || a == b {
		t.Fatalf("NewID = %q, %q; want two distinct UUIDv4", a, b)
	}
}

// TestAppend_OneLinePerRecord: the JSONL sink appends exactly one JSON
// line per record and creates the file owner-only.
func TestAppend_OneLinePerRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	rec, err := evidence.Build(baseInput())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := evidence.Append(path, rec); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("file has %d lines, want 2", len(lines))
	}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["specversion"] != "1.0" {
			t.Fatalf("line %q is not one CloudEvent", line)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 600", perm)
		}
	}
}

func TestAppend_UnwritableFails(t *testing.T) {
	rec, err := evidence.Build(baseInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.Append(t.TempDir(), rec); err == nil {
		t.Fatal("Append to a directory succeeded, want an error")
	}
}
