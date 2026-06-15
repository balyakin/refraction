package model

type Finding struct {
	RuleID      string     `json:"rule_id"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Title       string     `json:"title"`
	Message     string     `json:"message"`
	FilePath    string     `json:"file_path"`
	Line        int        `json:"line"`
	Region      RegionKind `json:"region"`
	Snippet     string     `json:"snippet"`
	Decoded     bool       `json:"decoded"`
	DecodePath  string     `json:"decode_path"`
	Suppressed  bool       `json:"suppressed"`
	Baseline    bool       `json:"baseline"`
	Fingerprint string     `json:"fingerprint"`
}

type ScanError struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func FindingStronger(a, b Finding) int {
	if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
		if SeverityRank(a.Severity) > SeverityRank(b.Severity) {
			return 1
		}
		return -1
	}
	if ConfidenceRank(a.Confidence) != ConfidenceRank(b.Confidence) {
		if ConfidenceRank(a.Confidence) > ConfidenceRank(b.Confidence) {
			return 1
		}
		return -1
	}
	if a.Decoded != b.Decoded {
		if a.Decoded {
			return 1
		}
		return -1
	}
	return 0
}
