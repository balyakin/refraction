package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/balyakin/refraction/internal/extract"
	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/normalize"
	"github.com/balyakin/refraction/internal/rules"
	"github.com/balyakin/refraction/internal/signatures"
)

var ErrNoEligible = errors.New("no files were eligible for scanning")

type UsageError struct {
	Message string
}

func (e *UsageError) Error() string {
	return e.Message
}

type Options struct {
	MinSeverity       model.Severity
	MinConfidence     model.Confidence
	MaxFileSize       int64
	MaxRegionSize     int
	MaxRegionsPerFile int
	ConfigPath        string
	BaselinePath      string
	IgnorePaths       []string
	RespectGitignore  bool
	Timeout           time.Duration
}

type Result struct {
	Findings        []model.Finding
	FilesScanned    int
	FilesSkipped    int
	SuppressedCount int
	BaselineCount   int
	Errors          []model.ScanError
	Duration        time.Duration
}

type configFile struct {
	Suppress          []suppression     `json:"suppress"`
	IgnorePaths       []string          `json:"ignore_paths"`
	SeverityOverrides map[string]string `json:"severity_overrides"`
}

type suppression struct {
	RuleID   string `json:"rule_id,omitempty"`
	Category string `json:"category,omitempty"`
	All      bool   `json:"all,omitempty"`
	PathGlob string `json:"path_glob,omitempty"`
	Reason   string `json:"reason"`
	Source   string `json:"-"`
}

func DefaultOptions() Options {
	return Options{
		MinSeverity:       model.SeverityInfo,
		MinConfidence:     model.ConfidenceLow,
		MaxFileSize:       5 * 1024 * 1024,
		MaxRegionSize:     65536,
		MaxRegionsPerFile: 10000,
		RespectGitignore:  true,
	}
}

func applyOptionDefaults(opts Options) Options {
	if opts.MinSeverity == "" {
		opts.MinSeverity = model.SeverityInfo
	}
	if opts.MinConfidence == "" {
		opts.MinConfidence = model.ConfidenceLow
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 5 * 1024 * 1024
	}
	if opts.MaxRegionSize <= 0 {
		opts.MaxRegionSize = 65536
	}
	if opts.MaxRegionsPerFile <= 0 {
		opts.MaxRegionsPerFile = 10000
	}
	return opts
}

func Scan(paths []string, opts Options) (Result, error) {
	opts = applyOptionDefaults(opts)
	start := time.Now()
	ctx := context.Background()
	cancel := func() {}
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}
	defer cancel()

	ruleData, allowData, err := signatures.Load()
	if err != nil {
		return Result{}, err
	}
	cfg, err := loadConfig(opts.ConfigPath, ruleData)
	if err != nil {
		return Result{}, err
	}
	engine, err := rules.New(ruleData, allowData, rules.Options{MaxRegionSize: opts.MaxRegionSize})
	if err != nil {
		return Result{}, err
	}
	baseline, err := ReadBaseline(opts.BaselinePath)
	if err != nil {
		return Result{}, err
	}

	base, files, skipped, walkErrs, err := collectFiles(ctx, paths, opts, cfg.IgnorePaths)
	if err != nil {
		return Result{}, err
	}
	result := Result{FilesSkipped: skipped, Errors: walkErrs}
	if len(files) == 0 {
		result.Duration = time.Since(start)
		return result, ErrNoEligible
	}

	result.Findings = append(result.Findings, filenameFindings(engine, files)...)
	fileResults, err := scanFiles(ctx, base, files, opts, engine)
	if err != nil {
		return result, err
	}
	readFailures := 0
	for _, fr := range fileResults {
		result.FilesScanned += fr.scanned
		result.FilesSkipped += fr.skipped
		readFailures += fr.readFailure
		result.Errors = append(result.Errors, fr.errors...)
		result.Findings = append(result.Findings, fr.findings...)
	}
	if result.FilesScanned == 0 {
		if readFailures == len(files) {
			result.Duration = time.Since(start)
			return result, fmt.Errorf("all eligible files failed to read")
		}
		if len(result.Findings) == 0 {
			result.Duration = time.Since(start)
			return result, ErrNoEligible
		}
	}
	finalize(&result, cfg, baseline)
	result.Duration = time.Since(start)
	_ = base
	return result, nil
}

func ScanReader(reader io.Reader, name string, opts Options) (Result, error) {
	opts = applyOptionDefaults(opts)
	start := time.Now()
	ruleData, allowData, err := signatures.Load()
	if err != nil {
		return Result{}, err
	}
	cfg, err := loadConfig(opts.ConfigPath, ruleData)
	if err != nil {
		return Result{}, err
	}
	engine, err := rules.New(ruleData, allowData, rules.Options{MaxRegionSize: opts.MaxRegionSize})
	if err != nil {
		return Result{}, err
	}
	baseline, err := ReadBaseline(opts.BaselinePath)
	if err != nil {
		return Result{}, err
	}
	limited := io.LimitReader(reader, opts.MaxFileSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Result{}, err
	}
	result := Result{}
	if int64(len(data)) > opts.MaxFileSize {
		result.FilesSkipped = 1
		result.Errors = append(result.Errors, model.ScanError{Path: filepath.ToSlash(name), Kind: "file_size", Message: "file exceeds maximum size"})
		result.Duration = time.Since(start)
		return result, nil
	}
	if isLargeAsset(filepath.ToSlash(name), int64(len(data))) {
		result.FilesSkipped = 1
		result.Errors = append(result.Errors, model.ScanError{Path: filepath.ToSlash(name), Kind: "asset", Message: "large image/font asset skipped"})
		result.Duration = time.Since(start)
		return result, nil
	}
	regions, errs := extract.Extract(filepath.ToSlash(name), data, extract.Options{MaxRegionSize: opts.MaxRegionSize, MaxRegionsPerFile: opts.MaxRegionsPerFile})
	result.Errors = append(result.Errors, errs...)
	text, _ := extract.DecodeText(data)
	inline, inlineErrs := parseInlineSuppressions(filepath.ToSlash(name), text)
	result.Errors = append(result.Errors, inlineErrs...)
	for _, region := range regions {
		findings := engine.MatchRegion(region)
		applyInline(findings, inline)
		result.Findings = append(result.Findings, findings...)
	}
	result.FilesScanned = 1
	finalize(&result, cfg, baseline)
	result.Duration = time.Since(start)
	return result, nil
}

type fileResult struct {
	findings    []model.Finding
	errors      []model.ScanError
	scanned     int
	skipped     int
	readFailure int
}

func scanFiles(ctx context.Context, base string, files []fileEntry, opts Options, engine *rules.Engine) ([]fileResult, error) {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > len(files) {
		workers = len(files)
	}
	jobs := make(chan int)
	results := make([]fileResult, len(files))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				select {
				case <-ctx.Done():
					results[idx] = fileResult{errors: []model.ScanError{{Path: files[idx].Rel, Kind: "timeout", Message: ctx.Err().Error()}}}
					continue
				default:
				}
				results[idx] = scanOneFile(ctx, files[idx], opts, engine)
			}
		}()
	}
	for i := range files {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return results, err
	}
	_ = base
	return results, nil
}

func scanOneFile(ctx context.Context, file fileEntry, opts Options, engine *rules.Engine) fileResult {
	info, err := os.Stat(file.Abs)
	if err != nil {
		return fileResult{skipped: 1, readFailure: 1, errors: []model.ScanError{{Path: file.Rel, Kind: "read", Message: err.Error()}}}
	}
	if info.Size() > opts.MaxFileSize {
		return fileResult{skipped: 1, errors: []model.ScanError{{Path: file.Rel, Kind: "file_size", Message: "file exceeds maximum size"}}}
	}
	if isLargeAsset(file.Rel, info.Size()) {
		return fileResult{skipped: 1, errors: []model.ScanError{{Path: file.Rel, Kind: "asset", Message: "large image/font asset skipped"}}}
	}
	f, err := os.Open(file.Abs)
	if err != nil {
		return fileResult{skipped: 1, readFailure: 1, errors: []model.ScanError{{Path: file.Rel, Kind: "read", Message: err.Error()}}}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, opts.MaxFileSize+1))
	if err != nil {
		return fileResult{skipped: 1, readFailure: 1, errors: []model.ScanError{{Path: file.Rel, Kind: "read", Message: err.Error()}}}
	}
	if int64(len(data)) > opts.MaxFileSize {
		return fileResult{skipped: 1, errors: []model.ScanError{{Path: file.Rel, Kind: "file_size", Message: "file exceeds maximum size"}}}
	}
	if err := ctx.Err(); err != nil {
		return fileResult{errors: []model.ScanError{{Path: file.Rel, Kind: "timeout", Message: err.Error()}}}
	}
	regions, errs := extract.Extract(file.Rel, data, extract.Options{MaxRegionSize: opts.MaxRegionSize, MaxRegionsPerFile: opts.MaxRegionsPerFile})
	text, _ := extract.DecodeText(data)
	inline, inlineErrs := parseInlineSuppressions(file.Rel, text)
	errs = append(errs, inlineErrs...)
	var findings []model.Finding
	for _, region := range regions {
		matches := engine.MatchRegion(region)
		applyInline(matches, inline)
		findings = append(findings, matches...)
	}
	return fileResult{findings: findings, errors: errs, scanned: 1}
}

func filenameFindings(engine *rules.Engine, files []fileEntry) []model.Finding {
	var findings []model.Finding
	byDir := map[string]map[string][]string{}
	for _, file := range files {
		dir := path.Dir(file.Rel)
		base := path.Base(file.Rel)
		key := normalize.FilenameKey(base)
		if key == "" {
			continue
		}
		if byDir[dir] == nil {
			byDir[dir] = map[string][]string{}
		}
		byDir[dir][key] = append(byDir[dir][key], file.Rel)
		findings = append(findings, engine.MatchRegion(model.Region{FilePath: file.Rel, Kind: model.RegionFilename, Line: 0, Text: base})...)
	}
	for _, keys := range byDir {
		for _, rels := range keys {
			if len(rels) < 2 {
				continue
			}
			sort.Strings(rels)
			for _, rel := range rels {
				text := "filename confusable collision: " + strings.Join(rels, " ")
				findings = append(findings, engine.MatchRegion(model.Region{FilePath: rel, Kind: model.RegionFilename, Line: 0, Text: text})...)
			}
		}
	}
	return findings
}

func finalize(result *Result, cfg configFile, baseline map[string]struct{}) {
	for i := range result.Findings {
		if sev, ok := cfg.SeverityOverrides[result.Findings[i].RuleID]; ok {
			result.Findings[i].Severity = model.Severity(sev)
		}
		if suppressedByConfig(result.Findings[i], cfg.Suppress) {
			result.Findings[i].Suppressed = true
		}
		if baseline != nil {
			if _, ok := baseline[result.Findings[i].Fingerprint]; ok {
				result.Findings[i].Baseline = true
			}
		}
	}
	result.Findings = rules.Deduplicate(result.Findings)
	result.SuppressedCount = 0
	result.BaselineCount = 0
	for _, finding := range result.Findings {
		if finding.Suppressed {
			result.SuppressedCount++
		}
		if finding.Baseline && !finding.Suppressed {
			result.BaselineCount++
		}
	}
	sortErrors(result.Errors)
}

func isLargeAsset(filePath string, size int64) bool {
	if size <= 256*1024 {
		return false
	}
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".ttf", ".otf", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func NewFindingCount(result Result, minSeverity model.Severity, minConfidence model.Confidence) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Suppressed || finding.Baseline {
			continue
		}
		if model.SeverityAtLeast(finding.Severity, minSeverity) && model.ConfidenceAtLeast(finding.Confidence, minConfidence) {
			count++
		}
	}
	return count
}

func sortErrors(errs []model.ScanError) {
	sort.SliceStable(errs, func(i, j int) bool {
		if errs[i].Path != errs[j].Path {
			return errs[i].Path < errs[j].Path
		}
		if errs[i].Kind != errs[j].Kind {
			return errs[i].Kind < errs[j].Kind
		}
		return errs[i].Message < errs[j].Message
	})
}

func loadConfig(file string, rulesData []model.Rule) (configFile, error) {
	cfg := configFile{SeverityOverrides: map[string]string{}}
	if file == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return cfg, &UsageError{Message: "read config: " + err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, &UsageError{Message: "invalid config: " + err.Error()}
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return cfg, &UsageError{Message: "invalid config: multiple JSON documents"}
	}
	if cfg.Suppress == nil {
		cfg.Suppress = []suppression{}
	}
	if cfg.IgnorePaths == nil {
		cfg.IgnorePaths = []string{}
	}
	if cfg.SeverityOverrides == nil {
		cfg.SeverityOverrides = map[string]string{}
	}
	known := map[string]struct{}{}
	for _, rule := range rulesData {
		known[rule.ID] = struct{}{}
	}
	for i := range cfg.Suppress {
		cfg.Suppress[i].Source = "config"
		if err := validateSuppression(cfg.Suppress[i], known); err != nil {
			return cfg, &UsageError{Message: "invalid config suppression: " + err.Error()}
		}
	}
	for id, sev := range cfg.SeverityOverrides {
		if _, ok := known[id]; !ok {
			return cfg, &UsageError{Message: "unknown severity override rule id: " + id}
		}
		if !model.ValidSeverity(model.Severity(sev)) {
			return cfg, &UsageError{Message: "invalid severity override for " + id + ": " + sev}
		}
	}
	return cfg, nil
}

func ExplainSeverityOverride(configPath string, ruleID string) (string, error) {
	if configPath == "" {
		return "", nil
	}
	rulesData, _, err := signatures.Load()
	if err != nil {
		return "", err
	}
	cfg, err := loadConfig(configPath, rulesData)
	if err != nil {
		return "", err
	}
	return cfg.SeverityOverrides[ruleID], nil
}

func validateSuppression(s suppression, known map[string]struct{}) error {
	if strings.TrimSpace(s.Reason) == "" {
		return fmt.Errorf("missing reason")
	}
	selectors := 0
	if s.RuleID != "" {
		selectors++
		if _, ok := known[s.RuleID]; !ok {
			return fmt.Errorf("unknown rule id %s", s.RuleID)
		}
	}
	if s.Category != "" {
		selectors++
		if !model.ValidCategory(model.Category(s.Category)) {
			return fmt.Errorf("invalid category %q", s.Category)
		}
	}
	if s.All {
		selectors++
	}
	if selectors != 1 {
		return fmt.Errorf("must include exactly one selector")
	}
	return nil
}

func suppressedByConfig(f model.Finding, suppressions []suppression) bool {
	for _, s := range suppressions {
		glob := s.PathGlob
		if glob == "" {
			glob = "**"
		}
		if !MatchGlob(glob, f.FilePath) {
			continue
		}
		if s.All || s.RuleID == f.RuleID || (s.Category != "" && model.Category(s.Category) == f.Category) {
			return true
		}
	}
	return false
}

type inlineSuppression struct {
	RuleID   string
	Category string
	All      bool
	Lines    map[int]struct{}
}

func parseInlineSuppressions(filePath string, text string) ([]inlineSuppression, []model.ScanError) {
	lines := strings.Split(text, "\n")
	var out []inlineSuppression
	var errs []model.ScanError
	for i, line := range lines {
		idx := strings.Index(line, "refraction:ignore")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("refraction:ignore"):])
		parts := strings.Fields(rest)
		if len(parts) < 2 {
			errs = append(errs, model.ScanError{Path: filePath, Kind: "suppression", Message: "inline suppression requires selector and reason"})
			continue
		}
		sel := parts[0]
		reason := strings.TrimSpace(strings.TrimPrefix(rest, sel))
		if reason == "" {
			errs = append(errs, model.ScanError{Path: filePath, Kind: "suppression", Message: "inline suppression requires reason"})
			continue
		}
		s := inlineSuppression{Lines: map[int]struct{}{i + 1: {}}}
		switch {
		case sel == "all":
			s.All = true
		case strings.HasPrefix(sel, "category:"):
			cat := strings.TrimPrefix(sel, "category:")
			if !model.ValidCategory(model.Category(cat)) {
				errs = append(errs, model.ScanError{Path: filePath, Kind: "suppression", Message: "invalid inline suppression category"})
				continue
			}
			s.Category = cat
		default:
			s.RuleID = sel
		}
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			s.Lines[j+1] = struct{}{}
			break
		}
		out = append(out, s)
	}
	return out, errs
}

func applyInline(findings []model.Finding, suppressions []inlineSuppression) {
	for i := range findings {
		for _, s := range suppressions {
			if _, ok := s.Lines[findings[i].Line]; !ok {
				continue
			}
			if s.All || s.RuleID == findings[i].RuleID || (s.Category != "" && model.Category(s.Category) == findings[i].Category) {
				findings[i].Suppressed = true
				break
			}
		}
	}
}
