package refraction

import (
	"io"
	"time"

	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/scan"
	"github.com/balyakin/refraction/internal/signatures"
)

type Options struct {
	MinSeverity       string
	MinConfidence     string
	MaxFileSize       int64
	MaxRegionSize     int
	MaxRegionsPerFile int
	ConfigPath        string
	BaselinePath      string
	IgnorePaths       []string
	RespectGitignore  bool
}

type Finding struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	FilePath    string `json:"file_path"`
	Line        int    `json:"line"`
	Region      string `json:"region"`
	Snippet     string `json:"snippet"`
	Decoded     bool   `json:"decoded"`
	DecodePath  string `json:"decode_path"`
	Suppressed  bool   `json:"suppressed"`
	Baseline    bool   `json:"baseline"`
	Fingerprint string `json:"fingerprint"`
}

type ScanError struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type Result struct {
	Findings        []Finding
	FilesScanned    int
	FilesSkipped    int
	SuppressedCount int
	BaselineCount   int
	Errors          []ScanError
	Duration        time.Duration
}

func DefaultOptions() Options {
	opts := scan.DefaultOptions()
	return Options{
		MinSeverity:       string(opts.MinSeverity),
		MinConfidence:     string(opts.MinConfidence),
		MaxFileSize:       opts.MaxFileSize,
		MaxRegionSize:     opts.MaxRegionSize,
		MaxRegionsPerFile: opts.MaxRegionsPerFile,
		RespectGitignore:  opts.RespectGitignore,
	}
}

func Scan(paths []string, opts Options) (Result, error) {
	internal, err := internalOptions(opts)
	if err != nil {
		return Result{}, err
	}
	result, err := scan.Scan(paths, internal)
	return externalResult(result), err
}

func ScanReader(reader io.Reader, name string, opts Options) (Result, error) {
	internal, err := internalOptions(opts)
	if err != nil {
		return Result{}, err
	}
	result, err := scan.ScanReader(reader, name, internal)
	return externalResult(result), err
}

func Version() string {
	return scan.ScannerVersion
}

func SignatureVersion() string {
	return signatures.SignatureVersion()
}

func internalOptions(opts Options) (scan.Options, error) {
	var sev model.Severity
	if opts.MinSeverity != "" {
		parsed, err := model.ParseSeverity(opts.MinSeverity)
		if err != nil {
			return scan.Options{}, err
		}
		sev = parsed
	}
	var conf model.Confidence
	if opts.MinConfidence != "" {
		parsed, err := model.ParseConfidence(opts.MinConfidence)
		if err != nil {
			return scan.Options{}, err
		}
		conf = parsed
	}
	return scan.Options{
		MinSeverity:       sev,
		MinConfidence:     conf,
		MaxFileSize:       opts.MaxFileSize,
		MaxRegionSize:     opts.MaxRegionSize,
		MaxRegionsPerFile: opts.MaxRegionsPerFile,
		ConfigPath:        opts.ConfigPath,
		BaselinePath:      opts.BaselinePath,
		IgnorePaths:       opts.IgnorePaths,
		RespectGitignore:  opts.RespectGitignore,
	}, nil
}

func externalResult(result scan.Result) Result {
	out := Result{
		FilesScanned:    result.FilesScanned,
		FilesSkipped:    result.FilesSkipped,
		SuppressedCount: result.SuppressedCount,
		BaselineCount:   result.BaselineCount,
		Duration:        result.Duration,
	}
	for _, finding := range result.Findings {
		out.Findings = append(out.Findings, Finding{
			RuleID:      finding.RuleID,
			Category:    string(finding.Category),
			Severity:    string(finding.Severity),
			Confidence:  string(finding.Confidence),
			Title:       finding.Title,
			Message:     finding.Message,
			FilePath:    finding.FilePath,
			Line:        finding.Line,
			Region:      string(finding.Region),
			Snippet:     finding.Snippet,
			Decoded:     finding.Decoded,
			DecodePath:  finding.DecodePath,
			Suppressed:  finding.Suppressed,
			Baseline:    finding.Baseline,
			Fingerprint: finding.Fingerprint,
		})
	}
	for _, err := range result.Errors {
		out.Errors = append(out.Errors, ScanError{Path: err.Path, Kind: err.Kind, Message: err.Message})
	}
	return out
}
