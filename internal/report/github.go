package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/balyakin/refraction/internal/model"
)

func RenderGitHub(w io.Writer, data Data, opts Options) error {
	if opts.Summary {
		return nil
	}
	for _, finding := range VisibleFindings(data.Findings) {
		level := "notice"
		switch finding.Severity {
		case model.SeverityCritical:
			level = "error"
		case model.SeverityWarning:
			level = "warning"
		}
		line := finding.Line
		if line <= 0 {
			line = 1
		}
		title := finding.RuleID + " " + finding.Title
		msg := finding.Message
		if finding.Snippet != "" {
			msg += " snippet: " + finding.Snippet
		}
		if _, err := fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n", level, escapeGHProp(finding.FilePath), line, escapeGHProp(title), escapeGHMessage(msg)); err != nil {
			return err
		}
	}
	return nil
}

func escapeGHProp(s string) string {
	s = escapeGHMessage(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

func escapeGHMessage(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
