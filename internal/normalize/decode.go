package normalize

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/balyakin/refraction/internal/model"
)

const (
	DefaultMaxDepth   = 2
	DefaultMinEntropy = 4.0
)

type Options struct {
	MaxSize    int
	MaxDepth   int
	MinEntropy float64
	EntropySet bool
}

func Expand(text string, opts Options) []model.Variant {
	if opts.MaxSize <= 0 {
		opts.MaxSize = 65536
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	if opts.MinEntropy <= 0 && !opts.EntropySet {
		opts.MinEntropy = DefaultMinEntropy
	}
	if len(text) > opts.MaxSize {
		text = text[:opts.MaxSize]
		text = strings.ToValidUTF8(text, "")
	}
	original := model.Variant{Text: strings.ToValidUTF8(text, ""), Decoded: false, DecodePath: ""}
	out := []model.Variant{original}
	seen := map[string]struct{}{variantKey(original): {}}
	frontier := []model.Variant{original}
	canonical := Canonicalize(original.Text)
	if canonical != original.Text {
		canonVariant := model.Variant{Text: canonical, Decoded: false, DecodePath: ""}
		if _, ok := seen[variantKey(canonVariant)]; !ok {
			seen[variantKey(canonVariant)] = struct{}{}
			out = append(out, canonVariant)
			frontier = append(frontier, canonVariant)
		}
	}
	for depth := 0; depth < opts.MaxDepth; depth++ {
		var next []model.Variant
		for _, cur := range frontier {
			for _, cand := range decodeOnce(cur, opts) {
				if len(cand.Text) > opts.MaxSize {
					continue
				}
				if !utf8.ValidString(cand.Text) || !MostlyPrintable(cand.Text) {
					continue
				}
				key := variantKey(cand)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, cand)
				next = append(next, cand)
			}
		}
		frontier = next
		if len(frontier) == 0 {
			break
		}
	}
	sort.SliceStable(out[1:], func(i, j int) bool {
		a, b := out[1:][i], out[1:][j]
		if a.DecodePath != b.DecodePath {
			return a.DecodePath < b.DecodePath
		}
		return a.Text < b.Text
	})
	return out
}

func variantKey(v model.Variant) string {
	return v.Text + "\x00" + strconv.FormatBool(v.Decoded) + "\x00" + v.DecodePath
}

type decoderCandidate struct {
	name string
	text string
}

func decodeOnce(v model.Variant, opts Options) []model.Variant {
	candidates := []decoderCandidate{}
	candidates = append(candidates, decodeBase64(v.Text, opts.MinEntropy)...)
	candidates = append(candidates, decodeHex(v.Text, opts.MinEntropy)...)
	candidates = append(candidates, decodeURL(v.Text)...)
	candidates = append(candidates, decodeUnicodeEscapes(v.Text)...)
	candidates = append(candidates, decodeHTMLEntities(v.Text)...)
	var out []model.Variant
	for _, c := range candidates {
		if c.text == "" || c.text == v.Text {
			continue
		}
		path := c.name
		if v.DecodePath != "" {
			path = v.DecodePath + ">" + c.name
		}
		out = append(out, model.Variant{Text: c.text, Decoded: true, DecodePath: path})
	}
	return out
}

var base64RE = regexp.MustCompile(`(?i)(?:base64\s*[:(]\s*)?([A-Za-z0-9+/_-]{16,}={0,2})`)

func decodeBase64(s string, minEntropy float64) []decoderCandidate {
	matches := base64RE.FindAllStringSubmatch(s, 32)
	var out []decoderCandidate
	for _, m := range matches {
		raw := strings.TrimSpace(m[1])
		if len(raw)%4 == 1 {
			continue
		}
		if ShannonEntropy(raw) < minEntropy && !strings.Contains(strings.ToLower(s), "base64") && !strings.Contains(strings.ToLower(s), "atob") {
			continue
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err := enc.DecodeString(raw)
			if err != nil {
				continue
			}
			text := strings.ToValidUTF8(string(decoded), "")
			if MostlyPrintable(text) {
				out = append(out, decoderCandidate{name: "base64", text: text})
			}
		}
	}
	return out
}

var hexRE = regexp.MustCompile(`(?i)(?:0x|hex\s*[:(]\s*)?([0-9a-f]{16,})`)

func decodeHex(s string, minEntropy float64) []decoderCandidate {
	matches := hexRE.FindAllStringSubmatch(s, 32)
	var out []decoderCandidate
	for _, m := range matches {
		raw := m[1]
		if len(raw)%2 != 0 {
			continue
		}
		if ShannonEntropy(raw) < minEntropy && !strings.Contains(strings.ToLower(s), "hex") && (minEntropy >= 5.0 || len(raw) < 32) {
			continue
		}
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			continue
		}
		text := strings.ToValidUTF8(string(decoded), "")
		if MostlyPrintable(text) {
			out = append(out, decoderCandidate{name: "hex", text: text})
		}
	}
	return out
}

func decodeURL(s string) []decoderCandidate {
	if !strings.Contains(s, "%") {
		return nil
	}
	decoded, ok := percentDecode(s)
	if !ok || decoded == s {
		return nil
	}
	return []decoderCandidate{{name: "url", text: decoded}}
}

func percentDecode(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v := fromHex(s[i+1])<<4 | fromHex(s[i+2])
			b.WriteByte(v)
			i += 2
			changed = true
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String(), changed
}

func isHex(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}

func fromHex(b byte) byte {
	switch {
	case '0' <= b && b <= '9':
		return b - '0'
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

var unicodeEscapeRE = regexp.MustCompile(`\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}|n|r|t|\\|"|')`)

func decodeUnicodeEscapes(s string) []decoderCandidate {
	if !unicodeEscapeRE.MatchString(s) {
		return nil
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		value, multibyte, tail, err := strconv.UnquoteChar(s[i:], '"')
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		changed = true
		if multibyte || value >= utf8.RuneSelf {
			b.WriteRune(value)
		} else {
			b.WriteByte(byte(value))
		}
		i = len(s) - len(tail) - 1
	}
	if !changed {
		return nil
	}
	decoded := b.String()
	if decoded == s {
		return nil
	}
	return []decoderCandidate{{name: "unicode_escape", text: decoded}}
}

func decodeHTMLEntities(s string) []decoderCandidate {
	if !strings.Contains(s, "&") {
		return nil
	}
	decoded := html.UnescapeString(s)
	if decoded == s {
		return nil
	}
	return []decoderCandidate{{name: "html_entity", text: decoded}}
}
