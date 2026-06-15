package model

import "testing"

func TestSeverityConfidenceParsingAndOrdering(t *testing.T) {
	if sev, err := ParseSeverity("warning"); err != nil || sev != SeverityWarning {
		t.Fatalf("ParseSeverity() = %q, %v", sev, err)
	}
	if _, err := ParseSeverity("loud"); err == nil {
		t.Fatalf("invalid severity accepted")
	}
	if conf, err := ParseConfidence("medium"); err != nil || conf != ConfidenceMedium {
		t.Fatalf("ParseConfidence() = %q, %v", conf, err)
	}
	if _, err := ParseConfidence("sure"); err == nil {
		t.Fatalf("invalid confidence accepted")
	}
	if !SeverityAtLeast(SeverityCritical, SeverityWarning) || SeverityAtLeast(SeverityInfo, SeverityWarning) {
		t.Fatalf("severity ordering is wrong")
	}
	if !ConfidenceAtLeast(ConfidenceHigh, ConfidenceMedium) || ConfidenceAtLeast(ConfidenceLow, ConfidenceMedium) {
		t.Fatalf("confidence ordering is wrong")
	}
}

func TestValidationHelpers(t *testing.T) {
	if !ValidCategory(CategoryPromptInjection) || ValidCategory("other") {
		t.Fatalf("category validation failed")
	}
	if !ValidRegion(RegionManifest) || ValidRegion("body") {
		t.Fatalf("region validation failed")
	}
	if !ValidMatchType(MatchRegex) || ValidMatchType("glob") {
		t.Fatalf("match type validation failed")
	}
	if !ValidStatus(RuleStatusDeprecated) || ValidStatus("removed") {
		t.Fatalf("status validation failed")
	}
}

func TestStrongerSelection(t *testing.T) {
	warning := Rule{Severity: SeverityWarning, Confidence: ConfidenceHigh}
	critical := Rule{Severity: SeverityCritical, Confidence: ConfidenceLow}
	if Stronger(critical, warning) <= 0 {
		t.Fatalf("critical rule should be stronger than warning")
	}
	low := Finding{Severity: SeverityWarning, Confidence: ConfidenceLow}
	high := Finding{Severity: SeverityWarning, Confidence: ConfidenceHigh}
	if FindingStronger(high, low) <= 0 {
		t.Fatalf("high-confidence finding should be stronger")
	}
	decoded := Finding{Severity: SeverityWarning, Confidence: ConfidenceHigh, Decoded: true}
	if FindingStronger(decoded, high) <= 0 {
		t.Fatalf("decoded finding should win when severity/confidence match")
	}
}
