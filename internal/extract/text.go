package extract

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/balyakin/refraction/internal/model"
)

func ExtractRawText(filePath string, text string, opts Options) []model.Region {
	regions, _ := ExtractRawTextWithErrors(filePath, text, opts)
	return regions
}

func ExtractRawTextWithErrors(filePath string, text string, opts Options) ([]model.Region, []model.ScanError) {
	c := newCollector(filePath, opts)
	c.add(model.RegionRawText, 1, text)
	return c.result()
}

func ExtractGeneric(filePath string, text string, opts Options) []model.Region {
	regions, _ := ExtractGenericWithErrors(filePath, text, opts)
	return regions
}

func ExtractGenericWithErrors(filePath string, text string, opts Options) ([]model.Region, []model.ScanError) {
	c := newCollector(filePath, opts)
	class := sourceClass(filePath)
	extractBlockComments(c, text)
	extractLineComments(c, text, class)
	extractStrings(c, text)
	extractHeredocs(c, text)
	extractNonASCIIIdentifierLines(c, text)
	if class == "plain" && len(c.regions) == 0 {
		c.add(model.RegionRawText, 1, text)
	}
	return c.result()
}

func extractLineComments(c *collector, text string, class string) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lineNo := i + 1
		if idx := strings.Index(line, "//"); idx >= 0 && class != "hash" {
			c.add(model.RegionComment, lineNo, line[idx+2:])
		}
		if class == "hash" {
			if idx := strings.Index(line, "#"); idx >= 0 {
				c.add(model.RegionComment, lineNo, line[idx+1:])
			}
		}
	}
}

func extractBlockComments(c *collector, text string) {
	line := 1
	for i := 0; i < len(text); {
		j := strings.Index(text[i:], "/*")
		if j < 0 {
			return
		}
		start := i + j
		line += strings.Count(text[i:start], "\n")
		endRel := strings.Index(text[start+2:], "*/")
		if endRel < 0 {
			c.add(model.RegionComment, line, text[start+2:])
			return
		}
		end := start + 2 + endRel
		c.add(model.RegionComment, line, text[start+2:end])
		line += strings.Count(text[start:end+2], "\n")
		i = end + 2
	}
}

func extractStrings(c *collector, text string) {
	line := 1
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '\n' {
			line++
			continue
		}
		if ch != '"' && ch != '\'' && ch != '`' {
			continue
		}
		quote := ch
		startLine := line
		start := i + 1
		if (quote == '"' || quote == '\'') && i+2 < len(text) && text[i+1] == quote && text[i+2] == quote {
			start = i + 3
			end := strings.Index(text[start:], string([]byte{quote, quote, quote}))
			if end < 0 {
				c.add(model.RegionString, startLine, text[start:])
				return
			}
			body := text[start : start+end]
			c.add(model.RegionString, startLine, body)
			line += strings.Count(text[i:start+end+3], "\n")
			i = start + end + 2
			continue
		}
		escaped := false
		for j := start; j < len(text); j++ {
			if text[j] == '\n' {
				line++
			}
			if quote != '`' && !escaped && text[j] == '\\' {
				escaped = true
				continue
			}
			if !escaped && text[j] == quote {
				c.add(model.RegionString, startLine, text[start:j])
				i = j
				break
			}
			escaped = false
			if j == len(text)-1 {
				c.add(model.RegionString, startLine, text[start:])
				i = j
			}
		}
	}
}

var heredocRE = regexp.MustCompile(`<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?`)

func extractHeredocs(c *collector, text string) {
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		m := heredocRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		marker := m[1]
		start := i + 1
		end := start
		for end < len(lines) && strings.TrimSpace(lines[end]) != marker {
			end++
		}
		if end > start {
			c.add(model.RegionString, start+1, strings.Join(lines[start:end], "\n"))
		}
		i = end
	}
}

func extractNonASCIIIdentifierLines(c *collector, text string) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if hasSuspiciousUnicode(line) {
			c.add(model.RegionRawText, i+1, line)
		}
	}
}

func hasSuspiciousUnicode(line string) bool {
	hasASCIIIdent := false
	hasOtherScript := false
	for _, r := range line {
		if r == '\u202A' || r == '\u202B' || r == '\u202C' || r == '\u202D' || r == '\u202E' || r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069' {
			return true
		}
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\u2060' || r == '\uFEFF' {
			return true
		}
		if r == '_' || ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z') {
			hasASCIIIdent = true
		}
		if unicode.In(r, unicode.Cyrillic, unicode.Greek) {
			hasOtherScript = true
		}
	}
	return hasASCIIIdent && hasOtherScript
}
