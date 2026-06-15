package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/balyakin/refraction/internal/model"
)

func ExtractManifest(filePath string, text string, opts Options) ([]model.Region, []model.ScanError) {
	c := newCollector(filePath, opts)
	manifestText := "path: " + filePath + "\n" + redactManifestSecrets(filePath, text)
	c.add(model.RegionManifest, 1, manifestText)
	if strings.EqualFold(path.Base(filePath), "package.json") {
		for _, dup := range duplicateJSONKeys([]byte(text)) {
			c.add(model.RegionManifest, dup.Line, fmt.Sprintf("duplicate JSON key: %s", dup.Key))
		}
	}
	extractNonASCIIIdentifierLines(c, text)
	return c.result()
}

func redactManifestSecrets(filePath, text string) string {
	base := strings.ToLower(path.Base(filePath))
	if base != ".npmrc" && base != ".yarnrc" && base != ".pypirc" {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "_auth") || strings.Contains(lower, "secret") {
			if idx := strings.IndexAny(line, "=:"); idx >= 0 {
				lines[i] = line[:idx+1] + "[redacted]"
			}
		}
	}
	return strings.Join(lines, "\n")
}

type duplicateKey struct {
	Key  string
	Line int
}

func duplicateJSONKeys(data []byte) []duplicateKey {
	dec := json.NewDecoder(bytes.NewReader(data))
	var out []duplicateKey
	scanJSONValue(dec, data, &out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func scanJSONValue(dec *json.Decoder, data []byte, out *[]duplicateKey) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return false
			}
			key, ok := keyTok.(string)
			if !ok {
				return false
			}
			if _, exists := seen[key]; exists {
				*out = append(*out, duplicateKey{Key: key, Line: lineForOffset(data, dec.InputOffset())})
			}
			seen[key] = struct{}{}
			if !scanJSONValue(dec, data, out) {
				return false
			}
		}
		_, _ = dec.Token()
	case '[':
		for dec.More() {
			if !scanJSONValue(dec, data, out) {
				return false
			}
		}
		_, _ = dec.Token()
	}
	return true
}

func lineForOffset(data []byte, off int64) int {
	if off < 0 {
		return 1
	}
	if off > int64(len(data)) {
		off = int64(len(data))
	}
	return bytes.Count(data[:off], []byte{'\n'}) + 1
}
