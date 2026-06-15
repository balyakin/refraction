package signatures

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/balyakin/refraction/internal/model"
)

const signatureVersion = "2026.06.15.1"

//go:embed data/*.json
var dataFS embed.FS

type envelope struct {
	Rules []model.Rule `json:"rules"`
}

func SignatureVersion() string {
	return signatureVersion
}

func Load() ([]model.Rule, []model.Rule, error) {
	ruleFiles := []string{
		"data/refusal_strings.json",
		"data/prompt_injection.json",
		"data/wmd_markers.json",
		"data/install_hooks.json",
		"data/obfuscation.json",
		"data/source_confusables.json",
		"data/manifest_tamper.json",
	}
	var findings []model.Rule
	seen := map[string]struct{}{}
	for _, name := range ruleFiles {
		env, err := readEnvelope(name)
		if err != nil {
			return nil, nil, err
		}
		for _, rule := range env.Rules {
			if err := validateFindingRule(rule); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			if _, ok := seen[rule.ID]; ok {
				return nil, nil, fmt.Errorf("%s: duplicate rule id %s", name, rule.ID)
			}
			seen[rule.ID] = struct{}{}
			findings = append(findings, rule)
		}
	}

	goodEnv, err := readEnvelope("data/good_content.json")
	if err != nil {
		return nil, nil, err
	}
	var allow []model.Rule
	for _, rule := range goodEnv.Rules {
		if err := validateAllowRule(rule); err != nil {
			return nil, nil, fmt.Errorf("data/good_content.json: %w", err)
		}
		if _, ok := seen[rule.ID]; ok {
			return nil, nil, fmt.Errorf("data/good_content.json: duplicate rule id %s", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		allow = append(allow, rule)
	}

	if err := validateReplacements(findings); err != nil {
		return nil, nil, err
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	sort.SliceStable(allow, func(i, j int) bool { return allow[i].ID < allow[j].ID })
	return findings, allow, nil
}

func Explain(id string) (model.Rule, bool, error) {
	rules, allow, err := Load()
	if err != nil {
		return model.Rule{}, false, err
	}
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true, nil
		}
	}
	for _, rule := range allow {
		if rule.ID == id {
			return rule, true, nil
		}
	}
	return model.Rule{}, false, nil
}

func ActiveRules() ([]model.Rule, error) {
	rules, _, err := Load()
	if err != nil {
		return nil, err
	}
	out := rules[:0]
	for _, rule := range rules {
		if rule.Status == model.RuleStatusActive {
			out = append(out, rule)
		}
	}
	return out, nil
}

func readEnvelope(name string) (envelope, error) {
	data, err := dataFS.ReadFile(name)
	if err != nil {
		return envelope{}, fmt.Errorf("%s: %w", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env envelope
	if err := dec.Decode(&env); err != nil {
		return envelope{}, fmt.Errorf("%s: invalid json: %w", name, err)
	}
	if len(env.Rules) == 0 {
		return envelope{}, fmt.Errorf("%s: no rules", name)
	}
	return env, nil
}

func validateFindingRule(rule model.Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("empty rule id")
	}
	if strings.HasPrefix(rule.ID, "GOOD") {
		return fmt.Errorf("%s: finding rule id may not use GOOD prefix", rule.ID)
	}
	if !model.ValidCategory(rule.Category) {
		return fmt.Errorf("%s: invalid category %q", rule.ID, rule.Category)
	}
	if !model.ValidSeverity(rule.Severity) {
		return fmt.Errorf("%s: invalid severity %q", rule.ID, rule.Severity)
	}
	if !model.ValidConfidence(rule.Confidence) {
		return fmt.Errorf("%s: invalid confidence %q", rule.ID, rule.Confidence)
	}
	if strings.TrimSpace(rule.Title) == "" || strings.TrimSpace(rule.Description) == "" || strings.TrimSpace(rule.Rationale) == "" || strings.TrimSpace(rule.Remediation) == "" {
		return fmt.Errorf("%s: missing required metadata", rule.ID)
	}
	return validateCommon(rule)
}

func validateAllowRule(rule model.Rule) error {
	if !strings.HasPrefix(rule.ID, "GOOD") {
		return fmt.Errorf("%s: allowlist rule id must use GOOD prefix", rule.ID)
	}
	if rule.Category != "" || rule.Severity != "" || rule.Confidence != "" {
		return fmt.Errorf("%s: allowlist rule must not set category, severity, or confidence", rule.ID)
	}
	if strings.TrimSpace(rule.Description) == "" || strings.TrimSpace(rule.Rationale) == "" {
		return fmt.Errorf("%s: missing allowlist metadata", rule.ID)
	}
	return validateCommon(rule)
}

func validateCommon(rule model.Rule) error {
	if !model.ValidMatchType(rule.MatchType) {
		return fmt.Errorf("%s: invalid match_type %q", rule.ID, rule.MatchType)
	}
	if !model.ValidStatus(rule.Status) {
		return fmt.Errorf("%s: invalid status %q", rule.ID, rule.Status)
	}
	if len(rule.Patterns) == 0 {
		return fmt.Errorf("%s: empty patterns", rule.ID)
	}
	for _, pattern := range rule.Patterns {
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("%s: empty pattern", rule.ID)
		}
		if rule.MatchType == model.MatchRegex {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("%s: invalid regex %q: %w", rule.ID, pattern, err)
			}
		}
	}
	for _, region := range rule.Regions {
		if !model.ValidRegion(model.RegionKind(region)) {
			return fmt.Errorf("%s: invalid region %q", rule.ID, region)
		}
	}
	return nil
}

func validateReplacements(rules []model.Rule) error {
	active := map[string]struct{}{}
	for _, rule := range rules {
		if rule.Status == model.RuleStatusActive {
			active[rule.ID] = struct{}{}
		}
	}
	for _, rule := range rules {
		if rule.ReplacedBy == "" {
			continue
		}
		if _, ok := active[rule.ReplacedBy]; !ok {
			return fmt.Errorf("%s: replaced_by references unknown active rule %s", rule.ID, rule.ReplacedBy)
		}
	}
	return nil
}
