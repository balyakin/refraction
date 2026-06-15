package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/balyakin/refraction/internal/model"
)

func sampleData() Data {
	finding := model.Finding{
		RuleID:      "PRM001",
		Category:    model.CategoryPromptInjection,
		Severity:    model.SeverityWarning,
		Confidence:  model.ConfidenceHigh,
		Title:       "Prompt injection",
		Message:     "Prompt override text.",
		FilePath:    "src/x.go",
		Line:        10,
		Region:      model.RegionComment,
		Snippet:     "[masked] pre...ous ins...ons",
		Fingerprint: "abc",
	}
	return Data{
		Version:          "0.1.0",
		SignatureVersion: "2026.06.14.1",
		FilesScanned:     1,
		Duration:         12 * time.Millisecond,
		Findings:         []model.Finding{finding},
		Rules: []model.Rule{{
			ID:          "PRM001",
			Title:       "Prompt injection",
			Description: "desc",
			Rationale:   "why",
			Remediation: "fix",
			Category:    model.CategoryPromptInjection,
			Severity:    model.SeverityWarning,
			Confidence:  model.ConfidenceHigh,
			Status:      model.RuleStatusActive,
			References:  []string{"https://example.invalid/refraction"},
		}},
	}
}

func TestRenderJSONDeterministic(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleData(), Options{Pretty: true}); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["version"] != "0.1.0" || parsed["duration_ms"].(float64) != 12 {
		t.Fatalf("unexpected json: %s", buf.String())
	}
	if _, ok := parsed["errors"].([]any); !ok {
		t.Fatalf("errors should be an array: %s", buf.String())
	}
	var summary bytes.Buffer
	if err := RenderJSON(&summary, sampleData(), Options{Summary: true}); err != nil {
		t.Fatal(err)
	}
	parsed = map[string]any{}
	if err := json.Unmarshal(summary.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if findings, ok := parsed["findings"].([]any); !ok || len(findings) != 0 {
		t.Fatalf("summary findings should be an empty array: %s", summary.String())
	}
}

func TestRenderNDJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderNDJSON(&buf, sampleData()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"rule_id":"PRM001"`) {
		t.Fatalf("unexpected ndjson: %q", buf.String())
	}
}

func TestRenderGitHubEscapes(t *testing.T) {
	data := sampleData()
	data.Findings[0].FilePath = "src/a,b.go"
	data.Findings[0].Message = "line1\nline2"
	var buf bytes.Buffer
	if err := RenderGitHub(&buf, data, Options{}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "a%2Cb.go") || strings.Contains(got, "\nline2") {
		t.Fatalf("github output not escaped: %q", got)
	}
	buf.Reset()
	if err := RenderGitHub(&buf, data, Options{Summary: true}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("summary github output should be empty: %q", buf.String())
	}
}

func TestRenderSARIFIncludesMetadataAndIgnoresPretty(t *testing.T) {
	data := sampleData()
	data.Findings[0].Baseline = true
	var sarif bytes.Buffer
	if err := RenderSARIF(&sarif, sampleData(), Options{Pretty: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sarif.String(), "\n  ") {
		t.Fatalf("sarif should ignore pretty option: %s", sarif.String())
	}
	if !strings.Contains(sarif.String(), `"version":"2.1.0"`) || !strings.Contains(sarif.String(), `"ruleId":"PRM001"`) {
		t.Fatalf("unexpected sarif: %s", sarif.String())
	}
	if !strings.Contains(sarif.String(), `"references":["`) {
		t.Fatalf("sarif missing references: %s", sarif.String())
	}
	sarif.Reset()
	if err := RenderSARIF(&sarif, data, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarif.String(), `"suppressions":[`) {
		t.Fatalf("sarif baseline missing suppression metadata: %s", sarif.String())
	}
}

func TestRenderSARIFAndMarkdown(t *testing.T) {
	var sarif bytes.Buffer
	sarif.Reset()
	if err := RenderSARIF(&sarif, sampleData(), Options{Summary: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarif.String(), `"results":[]`) && !strings.Contains(sarif.String(), `"results": []`) {
		t.Fatalf("summary sarif results should be an empty array: %s", sarif.String())
	}
	var md bytes.Buffer
	if err := RenderMarkdown(&md, sampleData(), Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "| Files scanned | 1 |") || strings.Contains(md.String(), "ignore previous instructions") {
		t.Fatalf("unexpected markdown: %s", md.String())
	}
}

func TestSummaryOmitsDetails(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, sampleData(), Options{Summary: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Prompt override") {
		t.Fatalf("summary contains details: %s", buf.String())
	}
}

func TestRenderTextColorKeepsANSICodesValid(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, sampleData(), Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "\x1b[33mWARNING\x1b[0m") {
		t.Fatalf("colored severity is malformed: %q", got)
	}
}
