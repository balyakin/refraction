package scan

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/balyakin/refraction/internal/model"
)

type IgnoreMatcher struct {
	patterns []string
}

func NewIgnoreMatcher(patterns []string) (IgnoreMatcher, []model.ScanError) {
	var matcher IgnoreMatcher
	var errs []model.ScanError
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		if strings.HasPrefix(p, "!") || strings.ContainsAny(p, "[]{}") {
			errs = append(errs, model.ScanError{Kind: "ignore", Message: "unsupported ignore pattern ignored: " + raw})
			continue
		}
		p = filepath.ToSlash(strings.TrimPrefix(p, "./"))
		matcher.patterns = append(matcher.patterns, p)
	}
	return matcher, errs
}

func (m IgnoreMatcher) Match(rel string, isDir bool) bool {
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	for _, pattern := range m.patterns {
		if matchIgnore(pattern, rel, isDir) {
			return true
		}
	}
	return false
}

func matchIgnore(pattern, rel string, isDir bool) bool {
	pattern = filepath.ToSlash(pattern)
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		if strings.HasSuffix(suffix, "/**") {
			dir := strings.TrimSuffix(suffix, "/**")
			return rel == dir || strings.HasPrefix(rel, dir+"/") || strings.Contains(rel, "/"+dir+"/")
		}
		return rel == suffix || strings.HasSuffix(rel, "/"+suffix) || globMatch(suffix, path.Base(rel))
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return rel == prefix || strings.HasPrefix(rel, prefix+"/")
	}
	if strings.HasSuffix(pattern, "/") {
		dir := strings.TrimSuffix(pattern, "/")
		if strings.Contains(dir, "/") {
			return (isDir && rel == dir) || strings.HasPrefix(rel, dir+"/")
		}
		return (isDir && (rel == dir || strings.HasSuffix(rel, "/"+dir))) || strings.HasPrefix(rel, dir+"/") || strings.Contains(rel, "/"+dir+"/")
	}
	if strings.Contains(pattern, "/") {
		if ok, _ := path.Match(pattern, rel); ok {
			return true
		}
		return rel == pattern || strings.HasPrefix(rel, pattern+"/")
	}
	if ok, _ := path.Match(pattern, path.Base(rel)); ok {
		return true
	}
	if rel == pattern || strings.HasSuffix(rel, "/"+pattern) {
		return true
	}
	return isDir && strings.HasPrefix(rel, pattern+"/")
}

func globMatch(pattern, rel string) bool {
	ok, err := path.Match(pattern, rel)
	return err == nil && ok
}

func MatchGlob(pattern, rel string) bool {
	if pattern == "" || pattern == "**" {
		return true
	}
	return matchIgnore(pattern, filepath.ToSlash(rel), false)
}

func defaultDeniedDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", "target", ".cache", ".idea":
		return true
	default:
		return false
	}
}
