package report

import (
	"encoding/json"
	"io"

	"github.com/balyakin/refraction/internal/model"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription,omitempty"`
	FullDescription  sarifText      `json:"fullDescription,omitempty"`
	Help             sarifText      `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text,omitempty"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifText          `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifSuppression struct {
	Kind string `json:"kind"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func RenderSARIF(w io.Writer, data Data, opts Options) error {
	findings := data.Findings
	if opts.Summary {
		findings = []model.Finding{}
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "refraction", SemanticVersion: data.Version, Rules: sarifRules(data.Rules)}},
			Results: []sarifResult{},
		}},
	}
	for _, finding := range findings {
		result := sarifResult{
			RuleID:  finding.RuleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifText{Text: finding.Message + " Snippet: " + finding.Snippet},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: finding.FilePath},
					Region:           sarifRegion{StartLine: sarifLine(finding.Line)},
				},
			}},
			Properties: map[string]any{
				"category":    finding.Category,
				"confidence":  finding.Confidence,
				"fingerprint": finding.Fingerprint,
				"decoded":     finding.Decoded,
				"decode_path": finding.DecodePath,
				"baseline":    finding.Baseline,
			},
		}
		if finding.Suppressed || finding.Baseline {
			result.Suppressions = []sarifSuppression{{Kind: "external"}}
		}
		log.Runs[0].Results = append(log.Runs[0].Results, result)
	}
	enc := json.NewEncoder(w)
	return enc.Encode(log)
}

func sarifRules(rules []model.Rule) []sarifRule {
	out := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Status != model.RuleStatusActive {
			continue
		}
		props := map[string]any{
			"category":   rule.Category,
			"severity":   rule.Severity,
			"confidence": rule.Confidence,
		}
		if len(rule.CWE) > 0 {
			props["cwe"] = rule.CWE
		}
		if len(rule.MITREAttack) > 0 {
			props["mitre_attack"] = rule.MITREAttack
		}
		if len(rule.References) > 0 {
			props["references"] = rule.References
		}
		out = append(out, sarifRule{
			ID:               rule.ID,
			Name:             rule.Title,
			ShortDescription: sarifText{Text: rule.Description},
			FullDescription:  sarifText{Text: rule.Rationale},
			Help:             sarifText{Text: rule.Remediation},
			Properties:       props,
		})
	}
	return out
}

func sarifLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "error"
	case model.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

func sarifLine(line int) int {
	if line <= 0 {
		return 1
	}
	return line
}
