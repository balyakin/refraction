package report

import (
	"fmt"
	"io"
	"strings"
)

func RenderMarkdown(w io.Writer, data Data, opts Options) error {
	visible := VisibleFindings(data.Findings)
	if _, err := fmt.Fprintf(w, "# refraction report\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "| Metric | Value |\n| --- | ---: |\n| Version | %s |\n| Signature version | %s |\n| Files scanned | %d |\n| Files skipped | %d |\n| Suppressed | %d |\n| Baseline | %d |\n| Duration | %dms |\n\n", data.Version, data.SignatureVersion, data.FilesScanned, data.FilesSkipped, data.SuppressedCount, data.BaselineCount, data.Duration.Milliseconds()); err != nil {
		return err
	}
	if opts.Summary {
		return nil
	}
	if len(visible) == 0 {
		_, err := fmt.Fprintln(w, "No new unsuppressed findings.")
		return err
	}
	for _, finding := range visible {
		line := "-"
		if finding.Line > 0 {
			line = fmt.Sprintf("%d", finding.Line)
		}
		if _, err := fmt.Fprintf(w, "## `%s` %s\n\n", finding.RuleID, escapeMarkdown(finding.Title)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "- Severity: `%s`\n- Confidence: `%s`\n- Category: `%s`\n- Location: `%s:%s`\n- Message: %s\n", finding.Severity, finding.Confidence, finding.Category, escapeMarkdown(finding.FilePath), line, escapeMarkdown(finding.Message)); err != nil {
			return err
		}
		if finding.Snippet != "" {
			if _, err := fmt.Fprintf(w, "- Snippet: `%s`\n", escapeMarkdown(finding.Snippet)); err != nil {
				return err
			}
		}
		if finding.Decoded {
			if _, err := fmt.Fprintf(w, "- Decoded: `true` via `%s`\n", escapeMarkdown(finding.DecodePath)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	return nil
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
