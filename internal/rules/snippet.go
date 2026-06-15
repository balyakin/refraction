package rules

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/balyakin/refraction/internal/model"
)

const MaxSnippetLength = 80

func Snippet(text string, matched string, category model.Category, decoded bool, decodePath string) string {
	if decoded {
		if decodePath == "" {
			return "[decoded content masked]"
		}
		return truncateSnippet("[decoded content masked via " + decodePath + "]")
	}
	clean := safeVisibleText(text)
	clean = strings.Join(strings.Fields(clean), " ")
	if clean == "" {
		clean = safeVisibleText(matched)
	}
	if category == model.CategoryWMDMarker || category == model.CategoryRefusalTrigger || category == model.CategoryPromptInjection {
		clean = maskTokens(clean)
	}
	return truncateSnippet(clean)
}

func truncateSnippet(s string) string {
	if utf8.RuneCountInString(s) <= MaxSnippetLength {
		return s
	}
	runes := []rune(s)
	return string(runes[:MaxSnippetLength-len("...")]) + "..."
}

func maskTokens(s string) string {
	fields := strings.Fields(s)
	for i, field := range fields {
		fields[i] = maskToken(field)
	}
	return strings.Join(fields, " ")
}

func maskToken(s string) string {
	prefix := ""
	suffix := ""
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		if isWordRune(r) {
			break
		}
		prefix += string(r)
		s = s[size:]
	}
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if isWordRune(r) {
			break
		}
		suffix = string(r) + suffix
		s = s[:len(s)-size]
	}
	if utf8.RuneCountInString(s) <= 8 {
		return prefix + "[masked]" + suffix
	}
	runes := []rune(s)
	return prefix + string(runes[:3]) + "..." + string(runes[len(runes)-3:]) + suffix
}

func isWordRune(r rune) bool {
	return r == '_' || r == '-' || r == '/' || r == ':' || r == '.' || ('0' <= r && r <= '9') || ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z') || r > 127
}

func safeVisibleText(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case isDangerousControl(r):
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isDangerousControl(r rune) bool {
	switch r {
	case '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069',
		'\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF':
		return true
	default:
		return false
	}
}
