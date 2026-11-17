package domain_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Cases ported verbatim from HagaHarness tests/helpers/separator-cases.mjs,
// whose pre-veil JS normaliser this replaces: the written form, and the
// canonical key it shares a pseudonym with (compact; E.164 for a phone).
var separatedCases = [][2]string{
	{"ES91 2100 0418 4502 0005 1332", "ES9121000418450200051332"},
	{"es91-2100-0418-4502-0005-1332", "ES9121000418450200051332"},
	{"ES91.2100.0418.4502.0005.1332", "ES9121000418450200051332"},
	{"12.345.678-Z", "12345678Z"},
	{"12 345 678 Z", "12345678Z"},
	{"12345678-z", "12345678Z"},
	{"X-1234567-L", "X1234567L"},
	{"600 12 34 56", "+34600123456"},
	{"600 123 456", "+34600123456"},
	{"600-123-456", "+34600123456"},
	{"+34 600 123 456", "+34600123456"},
	{"912 34 56 78", "+34912345678"},
	{"0034 600 123 456", "+34600123456"},
}

// Contexts the written form is accepted in (a CSV row, a label glued by
// "-" or "."), from the same file.
var separatedInContext = [][2]string{
	{"Ana,600 123 456", "600 123 456"},
	{"Tel-600 123 456", "600 123 456"},
	{"Tel.600 12 34 56", "600 12 34 56"},
}

var separatedUntouched = []string{
	"Ana600 123 456",
	"600 123 456a",
	"ref0034-600-123-456",
	"nomina_12.345.678-Z",
	"_600 123 456",
	"ES91 2100 0418 4502 0005 1332_b",
	"Factura 2024-001234, total 1.234,56 €, 12/03/2024",
	"Tel. ext. 600 12",
	"1.600 123 456",
	"CP 28001 600",
	"Importe: 600 123 456 €",
	"ES00 2100 0418 4502 0005 1332",
	"12.345.678-A",
	"X-1234567-A",
	"500 123 456",
	"600 1234 56",
	"Pedido 600 123 4567",
	"600 123 456 789",
	"789 600 123 456",
	"2 600 123 456",
	"1 700 000 000",
	"1-600-123-456",
	"600 123 456-789",
	"0,600 123 456",
	"600 123 456 euros",
	"600 123 456 EUR",
	"600 123 456 eur",
	"EUR 600 123 456",
	"600 123 456 USD",
	"600 123 456 $",
	"$ 600 123 456",
}

func detectSeparated(text string) []domain.Finding {
	reg := domain.NewRegistry(domain.NewDNIDetector(), domain.NewIBANDetector(), domain.NewPhoneDetector())
	return reg.DetectAll(domain.Event{Kind: domain.EventPromptSubmit, Text: text})
}

func TestSeparatedForms_AreDetectedWithCompactKey(t *testing.T) {
	for _, tc := range separatedCases {
		t.Run(tc[0], func(t *testing.T) {
			findings := detectSeparated("Dato: " + tc[0] + ".")
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			if findings[0].Match != tc[0] {
				t.Errorf("Match = %q, want the written form %q", findings[0].Match, tc[0])
			}
			if findings[0].Key != tc[1] {
				t.Errorf("Key = %q, want %q", findings[0].Key, tc[1])
			}
		})
	}
	for _, tc := range separatedInContext {
		t.Run(tc[0], func(t *testing.T) {
			findings := detectSeparated(tc[0])
			if len(findings) != 1 || findings[0].Match != tc[1] {
				t.Fatalf("got %+v, want one finding matching %q", findings, tc[1])
			}
		})
	}
}

func TestSeparatedForms_NearMissesAreLeftAlone(t *testing.T) {
	for _, text := range separatedUntouched {
		t.Run(text, func(t *testing.T) {
			if findings := detectSeparated(text); len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

// TestPolicy_SeparatedAndCompact_ShareOneToken proves the same DNI written
// two ways is one person to the model, and rehydrates to the compact form.
func TestPolicy_SeparatedAndCompact_ShareOneToken(t *testing.T) {
	registry := domain.NewRegistry(domain.NewDNIDetector(), domain.NewIBANDetector(), domain.NewPhoneDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostOpenCode,
		SessionID: "s1",
		Text:      "dni 12.345.678-Z y 12345678Z, tel 600 12 34 56",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
	}
	want := "dni [DNI-001] y [DNI-001], tel [TEL-001]"
	if decision.RedactedText != want {
		t.Errorf("RedactedText = %q, want %q", decision.RedactedText, want)
	}

	write, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventToolArgs,
		Host:      domain.HostOpenCode,
		SessionID: "s1",
		ToolName:  "write",
		Text:      "content=[DNI-001]",
		Fields:    map[string]string{"content": "[DNI-001]"},
	})
	if err != nil {
		t.Fatalf("Evaluate write: %v", err)
	}
	if got := write.RedactedFields["content"]; !strings.Contains(got, "12345678Z") {
		t.Errorf("rehydrated content = %q, want the compact DNI", got)
	}
}

// TestSeparatedForms_LinearTime keeps the scan linear on 1 MB of near misses.
func TestSeparatedForms_LinearTime(t *testing.T) {
	chunk := "600 12 34 5x 12.345.678 ES91 2100 0418 4502 0005 133 1.234,56 € "
	text := strings.Repeat(chunk, 1<<20/len(chunk))
	if findings := detectSeparated(text); len(findings) != 0 {
		t.Fatalf("got %d findings on near misses", len(findings))
	}
}

// TestPolicy_PhoneWithAndWithoutPrefix_NeitherLeaks is the threat model's
// check for one phone written bare and with its +34 prefix in the same
// event: both forms are replaced, so neither reaches the model in clear,
// and each marker rehydrates to a form of that same number. That the two
// forms share one marker is pinned by TestPolicy_OnePhoneEveryForm_OneMarker.
func TestPolicy_PhoneWithAndWithoutPrefix_NeitherLeaks(t *testing.T) {
	registry := domain.NewRegistry(domain.NewPhoneDetector())
	policy := domain.NewPolicy(registry, domain.NewMemoryPseudonymStore())

	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostOpenCode,
		SessionID: "s1",
		Text:      "tel 600123456 o +34 600 123 456",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
	}
	for _, clear := range []string{"600123456", "600 123 456"} {
		if strings.Contains(decision.RedactedText, clear) {
			t.Fatalf("RedactedText = %q still holds %q", decision.RedactedText, clear)
		}
	}
	markers := regexp.MustCompile(`\[TEL-\d{3}\]`).FindAllString(decision.RedactedText, -1)
	if len(markers) != 2 {
		t.Fatalf("RedactedText = %q, want both forms replaced by a TEL marker", decision.RedactedText)
	}

	for _, marker := range markers {
		write, err := policy.Evaluate(domain.Event{
			Kind:      domain.EventToolArgs,
			Host:      domain.HostOpenCode,
			SessionID: "s1",
			ToolName:  "write",
			Text:      "content=" + marker,
			Fields:    map[string]string{"content": marker},
		})
		if err != nil {
			t.Fatalf("Evaluate write: %v", err)
		}
		if got := write.RedactedFields["content"]; !strings.HasSuffix(got, "600123456") {
			t.Errorf("%s rehydrates to %q, want a form of 600123456", marker, got)
		}
	}
}
