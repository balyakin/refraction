package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/signatures"
)

type Data struct {
	Version          string
	SignatureVersion string
	FilesScanned     int
	FilesSkipped     int
	Duration         time.Duration
	Findings         []model.Finding
	SuppressedCount  int
	BaselineCount    int
	Errors           []model.ScanError
	Rules            []model.Rule
}

type Options struct {
	Summary bool
	Pretty  bool
	Color   bool
}

type jsonReport struct {
	Version          string            `json:"version"`
	SignatureVersion string            `json:"signature_version"`
	FilesScanned     int               `json:"files_scanned"`
	FilesSkipped     int               `json:"files_skipped"`
	DurationMS       int64             `json:"duration_ms"`
	Findings         []model.Finding   `json:"findings"`
	SuppressedCount  int               `json:"suppressed_count"`
	BaselineCount    int               `json:"baseline_count"`
	Errors           []model.ScanError `json:"errors"`
}

func RenderJSON(w io.Writer, data Data, opts Options) error {
	findings := data.Findings
	if opts.Summary {
		findings = []model.Finding{}
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	errs := data.Errors
	if errs == nil {
		errs = []model.ScanError{}
	}
	payload := jsonReport{
		Version:          data.Version,
		SignatureVersion: data.SignatureVersion,
		FilesScanned:     data.FilesScanned,
		FilesSkipped:     data.FilesSkipped,
		DurationMS:       data.Duration.Milliseconds(),
		Findings:         findings,
		SuppressedCount:  data.SuppressedCount,
		BaselineCount:    data.BaselineCount,
		Errors:           errs,
	}
	enc := json.NewEncoder(w)
	if opts.Pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(payload)
}

func BaseData(version string, filesScanned int, filesSkipped int, duration time.Duration, findings []model.Finding, suppressed int, baseline int, errs []model.ScanError, rules []model.Rule) Data {
	return Data{
		Version:          version,
		SignatureVersion: signatures.SignatureVersion(),
		FilesScanned:     filesScanned,
		FilesSkipped:     filesSkipped,
		Duration:         duration,
		Findings:         findings,
		SuppressedCount:  suppressed,
		BaselineCount:    baseline,
		Errors:           errs,
		Rules:            rules,
	}
}
