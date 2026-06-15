package rules

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/balyakin/refraction/internal/extract"
	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/normalize"
)

type Engine struct {
	rules      []compiledRule
	allow      []compiledRule
	maxSize    int
	minEntropy float64
}

type Options struct {
	MaxRegionSize int
	MinEntropy    float64
}

func New(ruleData []model.Rule, allowData []model.Rule, opts Options) (*Engine, error) {
	if opts.MaxRegionSize <= 0 {
		opts.MaxRegionSize = 65536
	}
	if opts.MinEntropy <= 0 {
		opts.MinEntropy = normalize.DefaultMinEntropy
	}
	engine := &Engine{maxSize: opts.MaxRegionSize, minEntropy: opts.MinEntropy}
	for _, rule := range ruleData {
		cr, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rule.ID, err)
		}
		engine.rules = append(engine.rules, cr)
	}
	for _, rule := range allowData {
		cr, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rule.ID, err)
		}
		engine.allow = append(engine.allow, cr)
	}
	return engine, nil
}

func (e *Engine) Rules() []model.Rule {
	out := make([]model.Rule, 0, len(e.rules))
	for _, cr := range e.rules {
		out = append(out, cr.rule)
	}
	return out
}

func (e *Engine) MatchRegion(region model.Region) []model.Finding {
	var findings []model.Finding
	variantCache := map[float64][]model.Variant{}
	for _, cr := range e.rules {
		if cr.rule.Status != model.RuleStatusActive || !cr.regionAllowed(region.Kind) {
			continue
		}
		minEntropy := e.ruleMinEntropy(cr.rule, region.FilePath)
		variants, ok := variantCache[minEntropy]
		if !ok {
			variants = normalize.Expand(region.Text, normalize.Options{
				MaxSize:    e.maxSize,
				MaxDepth:   normalize.DefaultMaxDepth,
				MinEntropy: minEntropy,
				EntropySet: true,
			})
			variantCache[minEntropy] = variants
		}
		for _, variant := range variants {
			if e.allowed(region, variant) {
				continue
			}
			matched, ok := cr.matchText(variant)
			if !ok {
				continue
			}
			findings = append(findings, model.Finding{
				RuleID:      cr.rule.ID,
				Category:    cr.rule.Category,
				Severity:    cr.rule.Severity,
				Confidence:  cr.rule.Confidence,
				Title:       cr.rule.Title,
				Message:     cr.rule.Description,
				FilePath:    filepath.ToSlash(region.FilePath),
				Line:        region.Line,
				Region:      region.Kind,
				Snippet:     Snippet(variant.Text, matched, cr.rule.Category, variant.Decoded, variant.DecodePath),
				Decoded:     variant.Decoded,
				DecodePath:  variant.DecodePath,
				Fingerprint: Fingerprint(cr.rule.ID, region.FilePath, region.Kind, variant.Decoded, matched),
			})
		}
	}
	return Deduplicate(findings)
}

func (e *Engine) ruleMinEntropy(rule model.Rule, filePath string) float64 {
	minEntropy := rule.MinEntropy
	if extract.IsHashBearingPath(filePath) && minEntropy < 5.0 {
		return 5.0
	}
	return minEntropy
}

func (e *Engine) allowed(region model.Region, variant model.Variant) bool {
	for _, cr := range e.allow {
		if cr.rule.Status != model.RuleStatusActive || !cr.regionAllowed(region.Kind) {
			continue
		}
		if _, ok := cr.matchText(variant); ok {
			return true
		}
	}
	return false
}

func Deduplicate(findings []model.Finding) []model.Finding {
	byFingerprint := map[string]model.Finding{}
	for _, finding := range findings {
		if existing, ok := byFingerprint[finding.Fingerprint]; ok {
			if preferFinding(finding, existing) {
				byFingerprint[finding.Fingerprint] = finding
			}
			continue
		}
		byFingerprint[finding.Fingerprint] = finding
	}
	out := make([]model.Finding, 0, len(byFingerprint))
	for _, finding := range byFingerprint {
		out = append(out, finding)
	}
	SortFindings(out)
	return out
}

func preferFinding(candidate model.Finding, existing model.Finding) bool {
	if candidate.Suppressed != existing.Suppressed {
		return !candidate.Suppressed
	}
	if candidate.Baseline != existing.Baseline {
		return !candidate.Baseline
	}
	return model.FindingStronger(candidate, existing) > 0
}

func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if model.SeverityRank(a.Severity) != model.SeverityRank(b.Severity) {
			return model.SeverityRank(a.Severity) < model.SeverityRank(b.Severity)
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Fingerprint < b.Fingerprint
	})
}
