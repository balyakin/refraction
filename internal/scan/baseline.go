package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/signatures"
)

const ScannerVersion = "0.1.0"

type Baseline struct {
	Version          string          `json:"version"`
	SignatureVersion string          `json:"signature_version"`
	CreatedAt        string          `json:"created_at"`
	Findings         []BaselineEntry `json:"findings"`
}

type BaselineEntry struct {
	Fingerprint string           `json:"fingerprint"`
	RuleID      string           `json:"rule_id,omitempty"`
	FilePath    string           `json:"file_path,omitempty"`
	Region      model.RegionKind `json:"region,omitempty"`
}

func ReadBaseline(path string) (map[string]struct{}, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &UsageError{Message: "read baseline: " + err.Error()}
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, &UsageError{Message: "invalid baseline: " + err.Error()}
	}
	out := map[string]struct{}{}
	for _, finding := range baseline.Findings {
		if finding.Fingerprint != "" {
			out[finding.Fingerprint] = struct{}{}
		}
	}
	return out, nil
}

func WriteBaseline(path string, findings []model.Finding, now time.Time) error {
	entries := make([]BaselineEntry, 0, len(findings))
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		entries = append(entries, BaselineEntry{
			Fingerprint: finding.Fingerprint,
			RuleID:      finding.RuleID,
			FilePath:    finding.FilePath,
			Region:      finding.Region,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].FilePath != entries[j].FilePath {
			return entries[i].FilePath < entries[j].FilePath
		}
		if entries[i].RuleID != entries[j].RuleID {
			return entries[i].RuleID < entries[j].RuleID
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
	baseline := Baseline{
		Version:          ScannerVersion,
		SignatureVersion: signatures.SignatureVersion(),
		CreatedAt:        now.UTC().Format(time.RFC3339),
		Findings:         entries,
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}
