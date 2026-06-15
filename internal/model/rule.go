package model

import "fmt"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type Category string

const (
	CategoryRefusalTrigger   Category = "refusal-trigger"
	CategoryPromptInjection  Category = "prompt-injection"
	CategoryWMDMarker        Category = "wmd-marker"
	CategoryObfuscation      Category = "obfuscation"
	CategoryInstallHook      Category = "install-hook"
	CategorySourceConfusable Category = "source-confusable"
	CategoryManifestTamper   Category = "manifest-tamper"
)

type RegionKind string

const (
	RegionComment  RegionKind = "comment"
	RegionString   RegionKind = "string"
	RegionRawText  RegionKind = "raw-text"
	RegionBinary   RegionKind = "binary"
	RegionManifest RegionKind = "manifest"
	RegionFilename RegionKind = "filename"
)

type MatchType string

const (
	MatchLiteral         MatchType = "literal"
	MatchAnyPhrase       MatchType = "any_phrase"
	MatchRegex           MatchType = "regex"
	MatchDecodedContains MatchType = "decoded_contains"
)

const (
	RuleStatusActive     = "active"
	RuleStatusDeprecated = "deprecated"
)

type Rule struct {
	ID                    string     `json:"id"`
	Category              Category   `json:"category,omitempty"`
	Severity              Severity   `json:"severity,omitempty"`
	Confidence            Confidence `json:"confidence,omitempty"`
	Title                 string     `json:"title,omitempty"`
	Description           string     `json:"description,omitempty"`
	Rationale             string     `json:"rationale,omitempty"`
	Remediation           string     `json:"remediation,omitempty"`
	AttackNarrative       string     `json:"attack_narrative,omitempty"`
	MatchType             MatchType  `json:"match_type"`
	Patterns              []string   `json:"patterns"`
	CaseInsensitive       bool       `json:"case_insensitive"`
	Regions               []string   `json:"regions,omitempty"`
	MinEntropy            float64    `json:"min_entropy,omitempty"`
	References            []string   `json:"references,omitempty"`
	CWE                   []string   `json:"cwe,omitempty"`
	MITREAttack           []string   `json:"mitre_attack,omitempty"`
	Ecosystems            []string   `json:"ecosystems,omitempty"`
	AttackExamples        []string   `json:"attack_examples,omitempty"`
	FalsePositiveExamples []string   `json:"false_positive_examples,omitempty"`
	Status                string     `json:"status,omitempty"`
	ReplacedBy            string     `json:"replaced_by,omitempty"`
}

func ValidSeverity(v Severity) bool {
	switch v {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	default:
		return false
	}
}

func ValidConfidence(v Confidence) bool {
	switch v {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

func ValidCategory(v Category) bool {
	switch v {
	case CategoryRefusalTrigger, CategoryPromptInjection, CategoryWMDMarker, CategoryObfuscation, CategoryInstallHook, CategorySourceConfusable, CategoryManifestTamper:
		return true
	default:
		return false
	}
}

func ValidRegion(v RegionKind) bool {
	switch v {
	case RegionComment, RegionString, RegionRawText, RegionBinary, RegionManifest, RegionFilename:
		return true
	default:
		return false
	}
}

func ValidMatchType(v MatchType) bool {
	switch v {
	case MatchLiteral, MatchAnyPhrase, MatchRegex, MatchDecodedContains:
		return true
	default:
		return false
	}
}

func ValidStatus(v string) bool {
	return v == RuleStatusActive || v == RuleStatusDeprecated
}

func SeverityRank(v Severity) int {
	switch v {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityCritical:
		return 2
	default:
		return -1
	}
}

func ConfidenceRank(v Confidence) int {
	switch v {
	case ConfidenceLow:
		return 0
	case ConfidenceMedium:
		return 1
	case ConfidenceHigh:
		return 2
	default:
		return -1
	}
}

func SeverityAtLeast(v, threshold Severity) bool {
	return SeverityRank(v) >= SeverityRank(threshold)
}

func ConfidenceAtLeast(v, threshold Confidence) bool {
	return ConfidenceRank(v) >= ConfidenceRank(threshold)
}

func Stronger(a, b Rule) int {
	if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
		if SeverityRank(a.Severity) > SeverityRank(b.Severity) {
			return 1
		}
		return -1
	}
	if ConfidenceRank(a.Confidence) != ConfidenceRank(b.Confidence) {
		if ConfidenceRank(a.Confidence) > ConfidenceRank(b.Confidence) {
			return 1
		}
		return -1
	}
	return 0
}

func ParseSeverity(v string) (Severity, error) {
	s := Severity(v)
	if !ValidSeverity(s) {
		return "", fmt.Errorf("invalid severity %q", v)
	}
	return s, nil
}

func ParseConfidence(v string) (Confidence, error) {
	c := Confidence(v)
	if !ValidConfidence(c) {
		return "", fmt.Errorf("invalid confidence %q", v)
	}
	return c, nil
}
