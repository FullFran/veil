package domain_test

import (
	"strings"
	"testing"

	"github.com/FullFran/veil/internal/domain"
)

// Cases from issue #24: values written with Unicode compatibility forms
// (full-width digits and letters, "＠") or with default-ignorable format
// characters inside them (U+200B and friends). A model reads them as the
// real value, so each one must be found, with the original written span
// as Match and the canonical value as Key. Values are synthetic.

func allDetectors() *domain.Registry {
	return domain.NewRegistry(
		domain.NewDNIDetector(),
		domain.NewEmailDetector(),
		domain.NewPhoneDetector(),
		domain.NewIBANDetector(),
		domain.NewNameCatalogDetector([]string{"María"}),
	)
}

func TestRegistry_DetectAll_Lookalikes(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []spanCase
	}{
		{
			name: "full-width forms",
			text: "dni １２３４５６７８Ｚ mail zed＠example.org tel ６１２３４５６７８",
			want: []spanCase{
				{match: "１２３４５６７８Ｚ", category: "DNI", key: "12345678Z"},
				{match: "zed＠example.org", category: "EMAIL", key: "zed@example.org"},
				{match: "６１２３４５６７８", category: "TEL", key: "+34612345678"},
			},
		},
		{
			name: "zero-width space inside the value",
			text: "dni 1234\u200b5678Z, zed@exa\u200bmple.org",
			want: []spanCase{
				{match: "1234\u200b5678Z", category: "DNI", key: "12345678Z"},
				{match: "zed@exa\u200bmple.org", category: "EMAIL", key: "zed@example.org"},
			},
		},
		{
			name: "other format characters",
			text: "tel 6\u200c1\u200d2\u20603\ufeff4\u00ad5678 ok",
			want: []spanCase{{match: "6\u200c1\u200d2\u20603\ufeff4\u00ad5678", category: "TEL", key: "+34612345678"}},
		},
		{
			name: "no-break spaces in a separated phone",
			text: "llama al 612\u00a0345\u202f678 hoy",
			want: []spanCase{{match: "612\u00a0345\u202f678", category: "TEL", key: "+34612345678"}},
		},
		{
			name: "decimal digits of another script",
			text: "tel \u0666\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668 ok",
			want: []spanCase{{match: "\u0666\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668", category: "TEL", key: "+34612345678"}},
		},
		{
			name: "full-width catalog name",
			text: "cita con Ｍａｒíａ mañana",
			want: []spanCase{{match: "Ｍａｒíａ", category: "NOMBRE", key: "María"}},
		},
		{
			name: "decomposed accent in a catalog name",
			text: "cita con Mari\u0301a mañana",
			want: []spanCase{{match: "Mari\u0301a", category: "NOMBRE", key: "María"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := allDetectors().DetectAll(promptEvent(tc.text))
			for _, want := range tc.want {
				assertSingleSpan(t, findings, want)
			}
			if len(findings) != len(tc.want) {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), len(tc.want), findings)
			}
		})
	}
}

// Text with nothing to normalize gives exactly the findings it gave
// before: same Match, and no Key added beyond the phone's own E.164 key.
func TestRegistry_DetectAll_PlainText_Unchanged(t *testing.T) {
	text := "Mi DNI es 12345678Z, mail zed@example.org, tel 612345678, María."
	findings := allDetectors().DetectAll(promptEvent(text))
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4: %+v", len(findings), findings)
	}
	for _, f := range findings {
		want := ""
		if f.Category == "TEL" {
			want = "+34612345678"
		}
		if f.Key != want {
			t.Errorf("finding %s has Key %q, want %q", f.Category, f.Key, want)
		}
	}
}

// A value written once plainly and once with lookalikes is reported
// once per written form, both keyed by the same canonical value.
func TestRegistry_DetectAll_PlainAndLookalike_SameKey(t *testing.T) {
	text := "12345678Z y １２３４５６７８Ｚ"
	findings := domain.NewRegistry(domain.NewDNIDetector()).DetectAll(promptEvent(text))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	if findings[0].Match != "12345678Z" || findings[1].Match != "１２３４５６７８Ｚ" || findings[1].Key != "12345678Z" {
		t.Fatalf("findings = %+v", findings)
	}
}

// The replaced span is the written one, unrelated lookalike text is left
// as written, and one value written two ways is one token.
func TestPolicy_Evaluate_Lookalikes_RewritesWrittenSpan(t *testing.T) {
	policy := domain.NewPolicy(allDetectors(), domain.NewMemoryPseudonymStore())
	decision, err := policy.Evaluate(domain.Event{
		Kind:      domain.EventPromptSubmit,
		Host:      domain.HostClaudeCode,
		SessionID: "s1",
		Text:      "ｈｏｌａ: dni １２３４５６７８Ｚ, 1234\u200b5678Z y 12345678Z",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Kind != domain.Rewrite {
		t.Fatalf("Kind = %v, want Rewrite", decision.Kind)
	}
	want := "ｈｏｌａ: dni [DNI-001], [DNI-001] y [DNI-001]"
	if decision.RedactedText != want {
		t.Fatalf("RedactedText = %q, want %q", decision.RedactedText, want)
	}
}

// Rehydration into a file writes the lookalike form as it was first
// written, so the bytes match the text the model was shown a token for;
// the token itself is keyed by the canonical value.
func TestPolicy_Evaluate_Lookalikes_RehydratesAsWritten(t *testing.T) {
	policy := domain.NewPolicy(allDetectors(), domain.NewMemoryPseudonymStore())
	first, err := policy.Evaluate(domain.Event{
		Kind: domain.EventPromptSubmit, Host: domain.HostOpenCode, SessionID: "s1",
		Text: "mail zed＠example.org",
	})
	if err != nil || first.Kind != domain.Rewrite {
		t.Fatalf("prompt: kind %v, err %v", first.Kind, err)
	}
	token := strings.TrimPrefix(first.RedactedText, "mail ")
	write, err := policy.Evaluate(domain.Event{
		Kind: domain.EventToolArgs, Host: domain.HostOpenCode, SessionID: "s1", ToolName: "write",
		Text:   "content: " + token,
		Fields: map[string]string{"content": token},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := write.RedactedFields["content"]; got != "zed＠example.org" {
		t.Fatalf("rehydrated content = %q, want the form first written", got)
	}
}
