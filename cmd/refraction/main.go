package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/balyakin/refraction/internal/model"
	"github.com/balyakin/refraction/internal/report"
	"github.com/balyakin/refraction/internal/scan"
	"github.com/balyakin/refraction/internal/signatures"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	opts := scan.DefaultOptions()
	var format string
	var outputFile string
	var minSeverity string
	var minConfidence string
	var timeoutText string
	var configPath string
	var baselinePath string
	var updateBaselinePath string
	var ignorePaths stringList
	var noRespectGitignore bool
	var noColor bool
	var pretty bool
	var summary bool
	var explainID string
	var listRules bool
	var showVersion bool

	fs := flag.NewFlagSet("refraction", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&format, "format", "text", "text|json|ndjson|sarif|github|markdown")
	fs.StringVar(&outputFile, "output-file", "", "write report to file")
	fs.StringVar(&minSeverity, "min-severity", string(opts.MinSeverity), "info|warning|critical")
	fs.StringVar(&minConfidence, "min-confidence", string(opts.MinConfidence), "low|medium|high")
	fs.Int64Var(&opts.MaxFileSize, "max-file-size", opts.MaxFileSize, "maximum file size in bytes")
	fs.IntVar(&opts.MaxRegionSize, "max-region-size", opts.MaxRegionSize, "maximum extracted region size")
	fs.IntVar(&opts.MaxRegionsPerFile, "max-regions-per-file", opts.MaxRegionsPerFile, "maximum extracted regions per file")
	fs.StringVar(&timeoutText, "timeout", "", "optional whole-scan timeout")
	fs.StringVar(&configPath, "config", "", "JSON config path")
	fs.StringVar(&baselinePath, "baseline", "", "baseline path")
	fs.StringVar(&updateBaselinePath, "update-baseline", "", "write baseline path")
	fs.Var(&ignorePaths, "ignore-path", "additional ignore glob")
	fs.BoolVar(&noRespectGitignore, "no-respect-gitignore", false, "disable .gitignore handling")
	fs.BoolVar(&noColor, "no-color", false, "disable color")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print JSON")
	fs.BoolVar(&summary, "summary", false, "summary only")
	fs.StringVar(&explainID, "explain", "", "explain rule")
	fs.BoolVar(&listRules, "list-rules", false, "list active rules")
	fs.BoolVar(&showVersion, "version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	infoCommands := 0
	if showVersion {
		infoCommands++
	}
	if listRules {
		infoCommands++
	}
	if explainID != "" {
		infoCommands++
	}
	if infoCommands > 1 {
		fmt.Fprintln(stderr, "--version, --list-rules, and --explain are mutually exclusive")
		return 2
	}
	if infoCommands > 0 && fs.NArg() > 0 {
		fmt.Fprintln(stderr, "--version, --list-rules, and --explain do not accept scan paths")
		return 2
	}
	if baselinePath != "" && updateBaselinePath != "" {
		fmt.Fprintln(stderr, "--baseline and --update-baseline are mutually exclusive")
		return 2
	}
	if summary && format == "ndjson" {
		fmt.Fprintln(stderr, "--summary is not valid with --format ndjson")
		return 2
	}
	if !validFormat(format) {
		fmt.Fprintln(stderr, "unknown format:", format)
		return 2
	}
	sev, err := model.ParseSeverity(minSeverity)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	conf, err := model.ParseConfidence(minConfidence)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	opts.MinSeverity = sev
	opts.MinConfidence = conf
	opts.ConfigPath = configPath
	opts.BaselinePath = baselinePath
	opts.IgnorePaths = ignorePaths
	opts.RespectGitignore = !noRespectGitignore
	if timeoutText != "" {
		timeout, err := time.ParseDuration(timeoutText)
		if err != nil {
			fmt.Fprintln(stderr, "invalid timeout:", err)
			return 2
		}
		opts.Timeout = timeout
	}

	if showVersion {
		fmt.Fprintf(stdout, "refraction %s signatures %s\n", scan.ScannerVersion, signatures.SignatureVersion())
		return 0
	}
	if listRules {
		return listRulesCommand(stdout, stderr)
	}
	if explainID != "" {
		return explainCommand(stdout, stderr, explainID, configPath)
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "missing scan path")
		return 2
	}

	if updateBaselinePath != "" {
		opts.BaselinePath = ""
	}
	result, err := scan.Scan(fs.Args(), opts)
	if err != nil {
		if errors.Is(err, scan.ErrNoEligible) {
			if !renderBestEffort(stdout, stderr, format, outputFile, result, summary, pretty, colorEnabled(stdout, noColor)) {
				return 3
			}
			return 4
		}
		var usage *scan.UsageError
		if errors.As(err, &usage) {
			fmt.Fprintln(stderr, usage.Message)
			return 2
		}
		fmt.Fprintln(stderr, err)
		return 3
	}

	if updateBaselinePath != "" {
		if err := scan.WriteBaseline(updateBaselinePath, result.Findings, time.Now()); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		return 0
	}
	if !renderBestEffort(stdout, stderr, format, outputFile, result, summary, pretty, colorEnabled(stdout, noColor)) {
		return 3
	}
	count := scan.NewFindingCount(result, opts.MinSeverity, opts.MinConfidence)
	if count > 0 {
		fmt.Fprintf(stderr, "%d new findings at severity >= %s and confidence >= %s\n", count, opts.MinSeverity, opts.MinConfidence)
		return 1
	}
	return 0
}

func validFormat(format string) bool {
	switch format {
	case "text", "json", "ndjson", "sarif", "github", "markdown":
		return true
	default:
		return false
	}
}

func renderBestEffort(stdout io.Writer, stderr io.Writer, format string, outputFile string, result scan.Result, summary bool, pretty bool, color bool) bool {
	var out io.Writer = stdout
	var file *os.File
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(stderr, "create output file %s: %v (parent directory must exist)\n", outputFile, err)
			return false
		}
		defer f.Close()
		file = f
		out = file
	}
	ruleData, _, err := signatures.Load()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return false
	}
	data := report.BaseData(scan.ScannerVersion, result.FilesScanned, result.FilesSkipped, result.Duration, result.Findings, result.SuppressedCount, result.BaselineCount, result.Errors, ruleData)
	opts := report.Options{Summary: summary, Pretty: pretty && format == "json", Color: color && outputFile == "" && format == "text"}
	switch format {
	case "text":
		err = report.RenderText(out, data, opts)
	case "json":
		err = report.RenderJSON(out, data, opts)
	case "ndjson":
		err = report.RenderNDJSON(out, data)
	case "sarif":
		err = report.RenderSARIF(out, data, opts)
	case "github":
		err = report.RenderGitHub(out, data, opts)
	case "markdown":
		err = report.RenderMarkdown(out, data, opts)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return false
	}
	return true
}

func listRulesCommand(stdout io.Writer, stderr io.Writer) int {
	rulesData, err := signatures.ActiveRules()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	fmt.Fprintf(stdout, "signature version: %s\n", signatures.SignatureVersion())
	for _, rule := range rulesData {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", rule.ID, rule.Severity, rule.Confidence, rule.Category, rule.Title)
	}
	return 0
}

func explainCommand(stdout io.Writer, stderr io.Writer, id string, configPath string) int {
	rule, ok, err := signatures.Explain(id)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if !ok {
		fmt.Fprintln(stderr, "unknown rule id:", id)
		return 2
	}
	fmt.Fprintf(stdout, "%s: %s\n", rule.ID, rule.Title)
	if rule.Category != "" {
		fmt.Fprintf(stdout, "category: %s\n", rule.Category)
	}
	if rule.Severity != "" {
		fmt.Fprintf(stdout, "severity: %s\n", rule.Severity)
	}
	if rule.Confidence != "" {
		fmt.Fprintf(stdout, "confidence: %s\n", rule.Confidence)
	}
	fmt.Fprintf(stdout, "status: %s\n", rule.Status)
	if rule.Description != "" {
		fmt.Fprintf(stdout, "\ndescription:\n%s\n", rule.Description)
	}
	if rule.Rationale != "" {
		fmt.Fprintf(stdout, "\nrationale:\n%s\n", rule.Rationale)
	}
	if rule.Remediation != "" {
		fmt.Fprintf(stdout, "\nremediation:\n%s\n", rule.Remediation)
	}
	if rule.AttackNarrative != "" {
		fmt.Fprintf(stdout, "\nattack narrative:\n%s\n", rule.AttackNarrative)
	}
	printList(stdout, "ecosystems", rule.Ecosystems)
	printList(stdout, "cwe", rule.CWE)
	printList(stdout, "mitre attack", rule.MITREAttack)
	printList(stdout, "attack examples", rule.AttackExamples)
	printList(stdout, "false-positive examples", rule.FalsePositiveExamples)
	printList(stdout, "references", rule.References)
	if configPath != "" {
		if override, err := scan.ExplainSeverityOverride(configPath, id); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		} else if override != "" {
			fmt.Fprintf(stdout, "\nconfig override:\nseverity is overridden to %s by %s\n", override, configPath)
		}
	}
	return 0
}

func printList(w io.Writer, title string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s:\n", title)
	for _, value := range values {
		fmt.Fprintf(w, "- %s\n", value)
	}
}

func colorEnabled(stdout io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := stdout.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
