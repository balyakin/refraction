package extract

import (
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/balyakin/refraction/internal/model"
)

type Options struct {
	MaxRegionSize     int
	MaxRegionsPerFile int
}

type Extractor interface {
	Extract(filePath string, text string, opts Options) ([]model.Region, []model.ScanError)
}

func Extract(filePath string, data []byte, opts Options) ([]model.Region, []model.ScanError) {
	opts = applyDefaults(opts)
	filePath = filepath.ToSlash(filePath)
	if IsManifestPath(filePath) {
		text, _ := DecodeText(data)
		return ExtractManifest(filePath, text, opts)
	}
	text, bomText := DecodeText(data)
	if !bomText && IsBinary(data) {
		return ExtractBinaryWithErrors(filePath, data, opts)
	}
	if IsRawTextPath(filePath) {
		return ExtractRawTextWithErrors(filePath, text, opts)
	}
	if strings.EqualFold(path.Ext(filePath), ".go") {
		return ExtractGo(filePath, text, opts)
	}
	return ExtractGenericWithErrors(filePath, text, opts)
}

func applyDefaults(opts Options) Options {
	if opts.MaxRegionSize <= 0 {
		opts.MaxRegionSize = 65536
	}
	if opts.MaxRegionsPerFile <= 0 {
		opts.MaxRegionsPerFile = 10000
	}
	return opts
}

type collector struct {
	filePath string
	opts     Options
	regions  []model.Region
	errs     []model.ScanError
	limited  bool
}

func newCollector(filePath string, opts Options) *collector {
	return &collector{filePath: filepath.ToSlash(filePath), opts: applyDefaults(opts)}
}

func (c *collector) add(kind model.RegionKind, line int, text string) {
	if c.limited {
		return
	}
	text = strings.ToValidUTF8(text, "")
	if text == "" {
		return
	}
	for len(text) > 0 {
		if len(c.regions) >= c.opts.MaxRegionsPerFile {
			c.errs = append(c.errs, model.ScanError{Path: c.filePath, Kind: "region_limit", Message: "maximum regions per file reached"})
			c.limited = true
			return
		}
		chunk := text
		if len(chunk) > c.opts.MaxRegionSize {
			chunk = trimUTF8(chunk[:c.opts.MaxRegionSize])
		}
		c.regions = append(c.regions, model.Region{FilePath: c.filePath, Kind: kind, Line: line, Text: chunk})
		if len(chunk) == len(text) {
			break
		}
		text = text[len(chunk):]
		if line > 0 {
			line += strings.Count(chunk, "\n")
		}
	}
}

func trimUTF8(s string) string {
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func (c *collector) result() ([]model.Region, []model.ScanError) {
	return c.regions, c.errs
}

func IsRawTextPath(filePath string) bool {
	switch strings.ToLower(path.Ext(filepath.ToSlash(filePath))) {
	case ".md", ".txt", ".rst", ".adoc", ".html", ".htm", ".svg":
		return true
	default:
		return false
	}
}

func IsManifestPath(filePath string) bool {
	p := filepath.ToSlash(filePath)
	base := path.Base(p)
	lowerBase := strings.ToLower(base)
	lowerPath := strings.ToLower(p)
	exact := map[string]bool{
		".gitattributes": true, ".gitmodules": true, ".npmrc": true, ".yarnrc": true, ".pypirc": true,
		"pkgbuild": true, "jenkinsfile": true, "package.json": true, "pyproject.toml": true, "setup.py": true,
		"cargo.toml": true, "build.rs": true, "gemfile": true, "pom.xml": true, "build.gradle": true,
		"build.gradle.kts": true, "settings.gradle": true, "settings.gradle.kts": true, "gradle.properties": true,
		"makefile": true, "dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
		".gitlab-ci.yml": true,
	}
	if exact[lowerBase] || exact[lowerPath] {
		return true
	}
	if lowerPath == ".circleci/config.yml" {
		return true
	}
	if strings.HasPrefix(lowerPath, ".github/workflows/") && (strings.HasSuffix(lowerPath, ".yml") || strings.HasSuffix(lowerPath, ".yaml")) {
		return true
	}
	switch {
	case strings.HasSuffix(lowerBase, ".install"), strings.HasSuffix(lowerBase, ".pth"), strings.HasSuffix(lowerBase, ".gemspec"):
		return true
	case strings.HasSuffix(lowerBase, ".csproj"), strings.HasSuffix(lowerBase, ".fsproj"), strings.HasSuffix(lowerBase, ".vbproj"), strings.HasSuffix(lowerBase, ".nuspec"):
		return true
	case strings.HasSuffix(lowerBase, ".tf"), strings.HasSuffix(lowerBase, ".tf.json"):
		return true
	default:
		return false
	}
}

func IsHashBearingPath(filePath string) bool {
	p := strings.ToLower(filepath.ToSlash(filePath))
	base := path.Base(p)
	switch base {
	case "go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "gemfile.lock", "composer.lock":
		return true
	}
	return strings.HasSuffix(base, ".sha256") || strings.HasSuffix(base, ".hash") || strings.HasSuffix(base, ".map") || strings.HasSuffix(base, ".wasm") || strings.Contains(base, ".min.")
}

func sourceClass(filePath string) string {
	switch strings.ToLower(path.Ext(filepath.ToSlash(filePath))) {
	case ".c", ".h", ".cpp", ".hpp", ".js", ".ts", ".tsx", ".jsx", ".rs", ".java", ".kt", ".swift", ".scala":
		return "c"
	case ".py", ".sh", ".rb", ".pl", ".yaml", ".yml", ".toml", ".tf", ".sql", ".lua", ".php":
		return "hash"
	default:
		return "plain"
	}
}
