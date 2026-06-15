package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/balyakin/refraction/internal/model"
)

type fileEntry struct {
	Abs string
	Rel string
}

func collectFiles(ctx context.Context, inputs []string, opts Options, extraIgnores []string) (string, []fileEntry, int, []model.ScanError, error) {
	if len(inputs) == 0 {
		return "", nil, 0, nil, &UsageError{Message: "missing scan path"}
	}
	absInputs := make([]string, 0, len(inputs))
	for _, input := range inputs {
		abs, err := filepath.Abs(filepath.Clean(input))
		if err != nil {
			return "", nil, 0, nil, err
		}
		absInputs = append(absInputs, abs)
	}
	sort.Strings(absInputs)
	absInputs = dedupeInputs(absInputs)
	base := scanBase(absInputs)
	patterns := append([]string{}, extraIgnores...)
	if opts.RespectGitignore {
		patterns = append(patterns, readIgnoreFile(filepath.Join(base, ".gitignore"))...)
	}
	patterns = append(patterns, readIgnoreFile(filepath.Join(base, ".refractionignore"))...)
	patterns = append(patterns, opts.IgnorePaths...)
	matcher, ignoreErrs := NewIgnoreMatcher(patterns)

	var files []fileEntry
	seenReal := map[string]struct{}{}
	skipped := 0
	for _, input := range absInputs {
		if err := ctx.Err(); err != nil {
			return base, files, skipped, ignoreErrs, err
		}
		info, err := os.Lstat(input)
		if err != nil {
			if os.IsNotExist(err) {
				return "", nil, 0, nil, &UsageError{Message: "missing scan path: " + input}
			}
			skipped++
			ignoreErrs = append(ignoreErrs, model.ScanError{Path: filepath.ToSlash(input), Kind: "walk", Message: err.Error()})
			continue
		}
		if info.IsDir() {
			err := filepath.WalkDir(input, func(p string, d os.DirEntry, err error) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err != nil {
					skipped++
					ignoreErrs = append(ignoreErrs, model.ScanError{Path: relPath(base, p), Kind: "walk", Message: err.Error()})
					if d != nil && d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if p == input {
					return nil
				}
				rel := relPath(base, p)
				name := d.Name()
				if d.IsDir() {
					if defaultDeniedDir(name) || matcher.Match(rel, true) {
						return filepath.SkipDir
					}
					return nil
				}
				if matcher.Match(rel, false) {
					skipped++
					return nil
				}
				if d.Type()&os.ModeSymlink != 0 {
					targetInfo, statErr := os.Stat(p)
					if statErr != nil {
						skipped++
						ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "symlink", Message: statErr.Error()})
						return nil
					}
					if targetInfo.IsDir() {
						skipped++
						ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "symlink", Message: "symlinked directory not traversed"})
						return nil
					}
					real, evalErr := filepath.EvalSymlinks(p)
					if evalErr != nil || !insideBase(base, real) {
						skipped++
						ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "symlink", Message: "symlink target outside scan base or unreadable"})
						return nil
					}
					addFile(&files, seenReal, real, rel)
					return nil
				}
				if d.Type().IsRegular() {
					addFile(&files, seenReal, p, rel)
				}
				return nil
			})
			if err != nil && !errors.Is(err, filepath.SkipDir) {
				return base, files, skipped, ignoreErrs, err
			}
			continue
		}
		rel := relPath(base, input)
		if matcher.Match(rel, false) {
			skipped++
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			targetInfo, statErr := os.Stat(input)
			if statErr != nil {
				skipped++
				ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "symlink", Message: statErr.Error()})
				continue
			}
			if targetInfo.IsDir() {
				skipped++
				ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "symlink", Message: "symlinked directory not traversed"})
				continue
			}
			if !targetInfo.Mode().IsRegular() {
				skipped++
				ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "walk", Message: "non-regular file skipped"})
				continue
			}
			real, evalErr := filepath.EvalSymlinks(input)
			if evalErr != nil || !insideBase(base, real) {
				skipped++
				ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "symlink", Message: "symlink target outside scan base or unreadable"})
				continue
			}
			addFile(&files, seenReal, real, rel)
			continue
		}
		if !info.Mode().IsRegular() {
			skipped++
			ignoreErrs = append(ignoreErrs, model.ScanError{Path: rel, Kind: "walk", Message: "non-regular file skipped"})
			continue
		}
		addFile(&files, seenReal, input, rel)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })
	return base, files, skipped, ignoreErrs, nil
}

func dedupeInputs(inputs []string) []string {
	out := make([]string, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, input := range inputs {
		key := input
		real, err := filepath.EvalSymlinks(input)
		if err == nil {
			key = real
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, input)
	}
	return out
}

func addFile(files *[]fileEntry, seen map[string]struct{}, abs string, rel string) {
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		real = abs
	}
	if _, ok := seen[real]; ok {
		return
	}
	seen[real] = struct{}{}
	*files = append(*files, fileEntry{Abs: abs, Rel: filepath.ToSlash(rel)})
}

func readIgnoreFile(file string) []string {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

func scanBase(absInputs []string) string {
	if len(absInputs) == 1 {
		info, err := os.Stat(absInputs[0])
		if err == nil && info.IsDir() {
			return absInputs[0]
		}
		return filepath.Dir(absInputs[0])
	}
	parents := make([]string, 0, len(absInputs))
	for _, input := range absInputs {
		parents = append(parents, existingParent(input))
	}
	return commonPath(parents)
}

func existingParent(p string) string {
	for {
		info, err := os.Stat(p)
		if err == nil {
			if info.IsDir() {
				return p
			}
			return filepath.Dir(p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

func commonPath(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	parts := strings.Split(filepath.Clean(paths[0]), string(filepath.Separator))
	for _, p := range paths[1:] {
		cur := strings.Split(filepath.Clean(p), string(filepath.Separator))
		n := len(parts)
		if len(cur) < n {
			n = len(cur)
		}
		i := 0
		for i < n && parts[i] == cur[i] {
			i++
		}
		parts = parts[:i]
	}
	if len(parts) == 0 {
		return string(filepath.Separator)
	}
	out := filepath.Join(parts...)
	if strings.HasPrefix(paths[0], string(filepath.Separator)) && !strings.HasPrefix(out, string(filepath.Separator)) {
		out = string(filepath.Separator) + out
	}
	return out
}

func relPath(base, p string) string {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(p))
	}
	if rel == "." {
		return filepath.ToSlash(filepath.Base(p))
	}
	return filepath.ToSlash(rel)
}

func insideBase(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
