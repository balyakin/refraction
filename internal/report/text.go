package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/balyakin/refraction/internal/model"
)

func RenderText(w io.Writer, data Data, opts Options) error {
	visible := VisibleFindings(data.Findings)
	sev := severityCounts(data.Findings)
	if _, err := fmt.Fprintf(w, "refraction %s (signatures %s)\n", data.Version, data.SignatureVersion); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "files scanned: %d, skipped: %d, duration: %dms\n", data.FilesScanned, data.FilesSkipped, data.Duration.Milliseconds()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "findings: critical=%d warning=%d info=%d, suppressed=%d, baseline=%d\n", sev[model.SeverityCritical], sev[model.SeverityWarning], sev[model.SeverityInfo], data.SuppressedCount, data.BaselineCount); err != nil {
		return err
	}
	if len(data.Errors) > 0 {
		if _, err := fmt.Fprintf(w, "errors: %d\n", len(data.Errors)); err != nil {
			return err
		}
	}
	if opts.Summary {
		return nil
	}
	if len(visible) == 0 {
		_, err := fmt.Fprintln(w, "no new unsuppressed findings")
		return err
	}
	for _, finding := range visible {
		level := strings.ToUpper(string(finding.Severity))
		if opts.Color {
			level = colorSeverity(finding.Severity, level)
		}
		line := "-"
		if finding.Line > 0 {
			line = fmt.Sprintf("%d", finding.Line)
		}
		if _, err := fmt.Fprintf(w, "\n%s %s %s:%s %s\n", level, finding.RuleID, finding.FilePath, line, finding.Title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %s\n", finding.Message); err != nil {
			return err
		}
		if finding.Snippet != "" {
			if _, err := fmt.Fprintf(w, "  snippet: %s\n", finding.Snippet); err != nil {
				return err
			}
		}
		if finding.Decoded {
			if _, err := fmt.Fprintf(w, "  decoded: true path=%s\n", finding.DecodePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func VisibleFindings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Suppressed || finding.Baseline {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func severityCounts(findings []model.Finding) map[model.Severity]int {
	out := map[model.Severity]int{
		model.SeverityInfo:     0,
		model.SeverityWarning:  0,
		model.SeverityCritical: 0,
	}
	for _, finding := range findings {
		if finding.Suppressed || finding.Baseline {
			continue
		}
		out[finding.Severity]++
	}
	return out
}

func colorSeverity(sev model.Severity, s string) string {
	switch sev {
	case model.SeverityCritical:
		return "\x1b[31m" + s + "\x1b[0m"
	case model.SeverityWarning:
		return "\x1b[33m" + s + "\x1b[0m"
	default:
		return "\x1b[36m" + s + "\x1b[0m"
	}
}
