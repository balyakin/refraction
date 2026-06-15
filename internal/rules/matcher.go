package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/normalize"
)

type compiledRule struct {
	rule     model.Rule
	regions  map[model.RegionKind]struct{}
	literals []string
	regexps  []*regexp.Regexp
}

func compileRule(rule model.Rule) (compiledRule, error) {
	cr := compiledRule{rule: rule, regions: map[model.RegionKind]struct{}{}}
	for _, region := range rule.Regions {
		cr.regions[model.RegionKind(region)] = struct{}{}
	}
	switch rule.MatchType {
	case model.MatchLiteral, model.MatchAnyPhrase, model.MatchDecodedContains:
		for _, pattern := range rule.Patterns {
			p := normalize.Canonicalize(pattern)
			if rule.CaseInsensitive {
				p = strings.ToLower(p)
			}
			cr.literals = append(cr.literals, p)
		}
	case model.MatchRegex:
		for _, pattern := range rule.Patterns {
			if rule.CaseInsensitive && !strings.HasPrefix(pattern, "(?i)") {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return compiledRule{}, err
			}
			cr.regexps = append(cr.regexps, re)
		}
	}
	return cr, nil
}

func (cr compiledRule) regionAllowed(kind model.RegionKind) bool {
	if len(cr.regions) == 0 {
		return true
	}
	_, ok := cr.regions[kind]
	return ok
}

func (cr compiledRule) matchText(v model.Variant) (string, bool) {
	if cr.rule.MatchType == model.MatchDecodedContains && !v.Decoded {
		return "", false
	}
	text := normalize.Canonicalize(v.Text)
	if cr.rule.MatchType == model.MatchRegex && cr.rule.Category == model.CategorySourceConfusable {
		text = v.Text
	}
	if cr.rule.CaseInsensitive {
		text = strings.ToLower(text)
	}
	switch cr.rule.MatchType {
	case model.MatchLiteral, model.MatchAnyPhrase, model.MatchDecodedContains:
		for _, pattern := range cr.literals {
			if strings.Contains(text, pattern) {
				return pattern, true
			}
		}
	case model.MatchRegex:
		for _, re := range cr.regexps {
			if loc := re.FindStringIndex(text); loc != nil {
				return text[loc[0]:loc[1]], true
			}
		}
	}
	return "", false
}

func Fingerprint(ruleID string, filePath string, region model.RegionKind, decoded bool, matchedText string) string {
	h := sha256.New()
	parts := []string{
		ruleID,
		filepath.ToSlash(filePath),
		string(region),
		boolString(decoded),
		normalize.FingerprintText(matchedText),
	}
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
