// Package evidence builds veil's decision evidence: one record per
// decision (allow, deny or rewrite) that says what veil decided, under
// which policy and which kinds of personal data it found, and never what
// that data was.
//
// A record is a CloudEvents 1.0.2 event in structured JSON mode whose
// data is an OCSF 1.9.0 Data Security Finding (class_uid 2006). Personal
// data categories are W3C DPV PD IRIs. A record never carries a detected
// value, a pseudonym token, a hash of a value, a field name or any input
// text (HCS-0005-R011): it is built only from a finding's detector id,
// the decision kind and metadata the host already exposes (host, event
// kind, tool name, session id).
package evidence

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"sort"
	"time"

	"github.com/FullFran/veil/internal/domain"
)

const (
	// Source is the CloudEvents source of every record: an RFC 4151 tag
	// URI, the same authority internal/problem uses for problem types.
	Source = "tag:fullfran.github.io,2026:veil"
	// Type is the CloudEvents type of a decision record, reverse-DNS of
	// the project's GitHub Pages host, versioned.
	Type = "io.github.fullfran.veil.decision.v1"
	// OCSFVersion is the OCSF schema version the data follows.
	OCSFVersion = "1.9.0"
	// DataSchema is the CloudEvents dataschema: the OCSF class the data
	// conforms to.
	DataSchema = "https://schema.ocsf.io/" + OCSFVersion + "/classes/data_security_finding"
	// SchemaVersion versions veil's own members under unmapped.veil.
	SchemaVersion = "1"
)

// OCSF constants for the Data Security Finding class.
const (
	categoryFindings     = 2
	classDataSecurity    = 2006
	activityCreate       = 1
	typeCreate           = classDataSecurity*100 + activityCreate
	detectionAppDLP      = 10 // data_security.detection_system_id: Application-Level DLP
	lifecycleInTransit   = 2  // data_security.data_lifecycle_state_id: Data in-Transit
	dataCategoryPersonal = 1
	dataCategorySecurity = 6
)

// dpvBase is the namespace of the W3C DPV personal data extension.
const dpvBase = "https://w3id.org/dpv/pd#"

// dpvByDetector maps a detector id to its DPV PD concept. It is keyed by
// detector, not by Finding.Category, because a deny action strips the
// category while the detector id stays.
var dpvByDetector = map[string]string{
	"name-catalog": dpvBase + "Name",
	"email":        dpvBase + "EmailAddress",
	"phone":        dpvBase + "TelephoneNumber",
	"dni":          dpvBase + "OfficialID",
	"iban":         dpvBase + "FinancialAccountNumber",
}

// labelByDetector is veil's own category label for each personal data
// detector: DPV has no DNI/NIE-specific term, so the label keeps the
// subtype next to the DPV IRI.
var labelByDetector = map[string]string{
	"name-catalog": "NOMBRE",
	"email":        "EMAIL",
	"phone":        "TEL",
	"dni":          "DNI",
	"iban":         "IBAN",
}

// Input is everything a record is built from. Findings are read only for
// their Detector; no other member of a domain.Finding reaches a record.
type Input struct {
	ID              string
	Time            time.Time
	Host            domain.Host
	Event           domain.EventKind
	Tool            string
	Session         string
	Action          domain.DecisionKind
	Findings        []domain.Finding
	PolicyDigest    string
	PolicyVersion   string
	CatalogRevision string
	Duration        time.Duration
}

// Record is a CloudEvents 1.0.2 event in structured JSON mode.
type Record struct {
	SpecVersion     string  `json:"specversion"`
	ID              string  `json:"id"`
	Source          string  `json:"source"`
	Type            string  `json:"type"`
	Time            string  `json:"time"`
	DataContentType string  `json:"datacontenttype"`
	DataSchema      string  `json:"dataschema"`
	Data            Finding `json:"data"`
}

// Finding is the OCSF Data Security Finding [2006] veil fills in.
type Finding struct {
	CategoryUID   int          `json:"category_uid"`
	ClassUID      int          `json:"class_uid"`
	ActivityID    int          `json:"activity_id"`
	TypeUID       int          `json:"type_uid"`
	SeverityID    int          `json:"severity_id"`
	Time          int64        `json:"time"`
	Metadata      Metadata     `json:"metadata"`
	FindingInfo   FindingInfo  `json:"finding_info"`
	ActionID      int          `json:"action_id"`
	Action        string       `json:"action"`
	DispositionID int          `json:"disposition_id"`
	Disposition   string       `json:"disposition"`
	Actor         Actor        `json:"actor"`
	DataSecurity  DataSecurity `json:"data_security"`
	Duration      int64        `json:"duration"`
	Unmapped      Unmapped     `json:"unmapped"`
}

// Metadata is OCSF metadata.
type Metadata struct {
	Version  string   `json:"version"`
	UID      string   `json:"uid"`
	Profiles []string `json:"profiles"`
	Product  Product  `json:"product"`
}

// Product is OCSF metadata.product.
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

// FindingInfo is OCSF finding_info.
type FindingInfo struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
}

// Actor is OCSF actor: the host, and its session when it gave one.
type Actor struct {
	AppName string   `json:"app_name"`
	Session *Session `json:"session,omitempty"`
}

// Session is OCSF session.
type Session struct {
	UID string `json:"uid"`
}

// DataSecurity is OCSF data_security.
type DataSecurity struct {
	DetectionSystemID    int               `json:"detection_system_id"`
	DataLifecycleStateID int               `json:"data_lifecycle_state_id"`
	CategoryID           int               `json:"category_id,omitempty"`
	Policy               Policy            `json:"policy"`
	DiscoveryDetails     []DiscoveryDetail `json:"discovery_details,omitempty"`
}

// Policy is OCSF policy: the veil policy digest and version.
type Policy struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	IsApplied bool   `json:"is_applied"`
}

// DiscoveryDetail is OCSF discovery_details: one detector's count. Its
// value and occurrences members are deliberately absent.
type DiscoveryDetail struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
	Rule  Rule   `json:"rule"`
}

// Rule is OCSF rule: the detector that fired.
type Rule struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
}

// Unmapped carries veil's members OCSF has no attribute for.
type Unmapped struct {
	Veil Veil `json:"veil"`
}

// Veil is the veil profile of a record.
type Veil struct {
	Schema          string `json:"schema"`
	Event           string `json:"event"`
	Tool            string `json:"tool,omitempty"`
	CatalogRevision string `json:"catalog_revision,omitempty"`
}

type verdict struct {
	actionID      int
	action        string
	dispositionID int
	disposition   string
	severityID    int
}

var verdicts = map[domain.DecisionKind]verdict{
	domain.Allow:   {1, "Allowed", 1, "Allowed", 1},
	domain.Deny:    {2, "Denied", 2, "Blocked", 3},
	domain.Rewrite: {4, "Modified", 99, "Pseudonymized", 2},
}

// Build turns in into a record. It fails for a decision kind that is not
// allow, deny or rewrite.
func Build(in Input) (Record, error) {
	v, ok := verdicts[in.Action]
	if !ok {
		return Record{}, fmt.Errorf("evidence: no verdict for decision kind %v", in.Action)
	}
	details, categoryID := discoveryDetails(in.Findings)
	actor := Actor{AppName: string(in.Host)}
	if in.Session != "" {
		actor.Session = &Session{UID: in.Session}
	}
	return Record{
		SpecVersion:     "1.0",
		ID:              in.ID,
		Source:          Source,
		Type:            Type,
		Time:            in.Time.UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		DataSchema:      DataSchema,
		Data: Finding{
			CategoryUID:   categoryFindings,
			ClassUID:      classDataSecurity,
			ActivityID:    activityCreate,
			TypeUID:       typeCreate,
			SeverityID:    v.severityID,
			Time:          in.Time.UnixMilli(),
			Metadata:      Metadata{Version: OCSFVersion, UID: in.ID, Profiles: []string{"security_control"}, Product: Product{Name: "veil", VendorName: "FullFran", Version: productVersion()}},
			FindingInfo:   FindingInfo{UID: in.ID, Title: "veil privacy decision"},
			ActionID:      v.actionID,
			Action:        v.action,
			DispositionID: v.dispositionID,
			Disposition:   v.disposition,
			Actor:         actor,
			DataSecurity: DataSecurity{
				DetectionSystemID:    detectionAppDLP,
				DataLifecycleStateID: lifecycleInTransit,
				CategoryID:           categoryID,
				Policy:               Policy{UID: in.PolicyDigest, Name: "veil policy", Version: in.PolicyVersion, IsApplied: true},
				DiscoveryDetails:     details,
			},
			Duration: in.Duration.Milliseconds(),
			Unmapped: Unmapped{Veil: Veil{Schema: SchemaVersion, Event: string(in.Event), Tool: in.Tool, CatalogRevision: in.CatalogRevision}},
		},
	}, nil
}

// discoveryDetails counts findings per detector, sorted by detector id,
// and returns the OCSF data category: Personal when any personal data
// detector fired, Security when only others did, 0 (omitted) for none.
func discoveryDetails(findings []domain.Finding) ([]DiscoveryDetail, int) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Detector]++
	}
	if len(counts) == 0 {
		return nil, 0
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	category := dataCategorySecurity
	details := make([]DiscoveryDetail, 0, len(ids))
	for _, id := range ids {
		typ, personal := dpvByDetector[id]
		name := labelByDetector[id]
		if personal {
			category = dataCategoryPersonal
		} else {
			typ, name = id, id
		}
		details = append(details, DiscoveryDetail{Type: typ, Count: counts[id], Rule: Rule{UID: id, Name: name}})
	}
	return details, category
}

// productVersion is veil's module version from the build info, or
// "(devel)" when it is not a released build.
func productVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

// ErrRevisionInvalid marks a catalog revision that is not an opaque token.
var ErrRevisionInvalid = errors.New("evidence: catalog revision must match [A-Za-z0-9._:-]{1,128}")

var revisionPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidateRevision checks a host-supplied catalog revision. veil emits
// it as-is and never derives it from the catalog's names.
func ValidateRevision(s string) error {
	if !revisionPattern.MatchString(s) {
		return ErrRevisionInvalid
	}
	return nil
}

// NewID returns a random RFC 9562 version 4 UUID for a record id.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Marshal returns rec as compact JSON.
func Marshal(rec Record) ([]byte, error) {
	return json.Marshal(rec)
}

// Append writes rec as one JSON line at the end of the file at path,
// creating it owner-only (0600). The line goes out in a single write on
// an O_APPEND descriptor, so concurrent veil processes never interleave
// records. Any error means the record was not durably appended.
func Append(path string, rec Record) error {
	b, err := Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- the host chooses the evidence file (VEIL_EVIDENCE_FILE)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close() // the write error is the one to report
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close() // the sync error is the one to report
		return err
	}
	return f.Close()
}
