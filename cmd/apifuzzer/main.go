package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/api-fuzzer/apifuzzer/internal/analyzer"
	"github.com/api-fuzzer/apifuzzer/internal/audit"
	"github.com/api-fuzzer/apifuzzer/internal/checkpoint"
	"github.com/api-fuzzer/apifuzzer/internal/config"
	"github.com/api-fuzzer/apifuzzer/internal/core"
	"github.com/api-fuzzer/apifuzzer/internal/deduplicator"
	"github.com/api-fuzzer/apifuzzer/internal/fuzzer"
	"github.com/api-fuzzer/apifuzzer/internal/openapi"
	"github.com/api-fuzzer/apifuzzer/internal/progress"
	"github.com/api-fuzzer/apifuzzer/internal/ratelimiter"
	"github.com/api-fuzzer/apifuzzer/internal/reporter"
	"github.com/api-fuzzer/apifuzzer/internal/rules"
	"github.com/api-fuzzer/apifuzzer/internal/scheduler"
	"github.com/api-fuzzer/apifuzzer/internal/stateful"
	"github.com/api-fuzzer/apifuzzer/internal/tui"
)

var (
	version = "2.0.0"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	switch command {
	case "fuzz", "":
		os.Exit(runFuzzCommand())
	case "audit":
		os.Exit(runAuditCommand())
	case "all":
		os.Exit(runAllCommand())
	case "version", "--version", "-v":
		fmt.Printf("api-fuzzer v%s\n", version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`API Fuzzer - Comprehensive API Security Testing Tool

Usage:
  apifuzzer <command> [flags]

Commands:
  fuzz    Run API fuzzing tests (default command)
  audit   Run API compliance audit
  all     Run both fuzzing and audit
  version Show version information
  help    Show this help message

Common Flags:
  --spec <path>         Path to OpenAPI spec file (JSON/YAML)
  --url <url>           Target API base URL
  --token <token>       Bearer token for authentication
  --api-key <key>       API key for authentication
  --auth-type <type>    Authentication type: bearer, apikey, basic, oauth2
  --qps <int>           Queries per second limit (default: 10)
  --timeout <duration>  Overall scan timeout (default: 30m)

Use "apifuzzer <command> --help" for more information about a command.`)
}

func runFuzzCommand() int {
	fuzzCmd := flag.NewFlagSet("fuzz", flag.ExitOnError)

	var (
		specPath    = fuzzCmd.String("spec", "", "Path to OpenAPI spec file (JSON/YAML)")
		targetURL   = fuzzCmd.String("url", "", "Target API base URL (overrides spec servers)")
		configPath  = fuzzCmd.String("config", "", "Path to YAML configuration file")
		seed        = fuzzCmd.Int64("seed", 0, "Random seed for reproducible tests (0 = random)")
		outputDir   = fuzzCmd.String("output", "./reports", "Output directory for reports")
		format      = fuzzCmd.String("format", "terminal,json", "Output formats: terminal,json,html,sarif (comma-separated)")
		qps         = fuzzCmd.Int("qps", 10, "Queries per second limit")
		concurrency = fuzzCmd.Int("concurrency", 5, "Concurrent requests limit")
		maxTests    = fuzzCmd.Int("max-tests", 1000, "Maximum number of test cases")
		stateful    = fuzzCmd.Bool("stateful", true, "Enable stateful fuzzing (CRUD chains)")
		authType    = fuzzCmd.String("auth-type", "", "Authentication type: bearer,apikey,basic,oauth2")
		token       = fuzzCmd.String("token", "", "Bearer token (or set API_FUZZER_BEARER_TOKEN env)")
		apiKey      = fuzzCmd.String("api-key", "", "API key (or set API_FUZZER_API_KEY env)")
		apiKeyName  = fuzzCmd.String("api-key-name", "X-API-Key", "API key header/query name")
		apiKeyIn    = fuzzCmd.String("api-key-in", "header", "API key location: header,query,cookie")
		failOn      = fuzzCmd.String("fail-on", "high", "Fail on severity: critical,high,medium,low,info")
		baseline    = fuzzCmd.String("baseline", "", "Path to baseline report (ignore known issues)")
		rulesPath   = fuzzCmd.String("rules", "", "Path to custom rules YAML file")
		timeout     = fuzzCmd.Duration("timeout", 30*time.Minute, "Overall scan timeout")
		exportGraph = fuzzCmd.String("export-graph", "", "Export dependency graph to DOT file")
		interactive = fuzzCmd.Bool("interactive", false, "Enable interactive TUI mode")
		resume      = fuzzCmd.String("resume", "", "Resume from checkpoint file")
		help        = fuzzCmd.Bool("help", false, "Show help for fuzz command")
	)

	fuzzCmd.Parse(os.Args[1:])

	if *help {
		fmt.Println(`Fuzz Command - Run API fuzzing tests

Usage:
  apifuzzer fuzz [flags]

Flags:
  --spec <path>         Path to OpenAPI spec file (JSON/YAML)
  --url <url>           Target API base URL (overrides spec servers)
  --config <path>       Path to YAML configuration file
  --seed <int>          Random seed for reproducible tests (0 = random)
  --output <dir>        Output directory for reports (default: ./reports)
  --format <formats>    Output formats: terminal,json,html,sarif (comma-separated)
  --qps <int>           Queries per second limit (default: 10)
  --concurrency <int>   Concurrent requests limit (default: 5)
  --max-tests <int>     Maximum number of test cases (default: 1000)
  --stateful <bool>     Enable stateful fuzzing (CRUD chains) (default: true)
  --auth-type <type>    Authentication type: bearer,apikey,basic,oauth2
  --token <token>       Bearer token
  --api-key <key>       API key
  --api-key-name <name> API key header/query name (default: X-API-Key)
  --api-key-in <loc>    API key location: header,query,cookie (default: header)
  --fail-on <severity>  Fail on severity: critical,high,medium,low,info (default: high)
  --baseline <path>     Path to baseline report (ignore known issues)
  --rules <path>        Path to custom rules YAML file
  --timeout <duration>  Overall scan timeout (default: 30m)
  --export-graph <path> Export dependency graph to DOT file
  --interactive         Enable interactive TUI mode
  --resume <path>       Resume from checkpoint file
  --help                Show this help message`)
		return 0
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return 1
	}

	cfg.Interactive = *interactive
	cfg.ResumeFile = *resume

	if *specPath != "" {
		cfg.OpenAPISpec = *specPath
	}
	if *targetURL != "" {
		cfg.TargetURL = *targetURL
	}
	if *seed != 0 {
		cfg.Fuzz.Seed = *seed
	}
	if *qps > 0 {
		cfg.RateLimit.QPS = *qps
	}
	if *concurrency > 0 {
		cfg.RateLimit.Concurrency = *concurrency
	}
	if *maxTests > 0 {
		cfg.Fuzz.MaxTestCases = *maxTests
	}
	if !*stateful {
		cfg.Fuzz.Stateful = false
	}
	if *authType != "" {
		cfg.Auth.Type = *authType
	}
	if *token != "" {
		cfg.Auth.BearerToken = *token
	}
	if *apiKey != "" {
		cfg.Auth.APIKey = *apiKey
	}
	if *apiKeyName != "" {
		cfg.Auth.APIKeyName = *apiKeyName
	}
	if *apiKeyIn != "" {
		cfg.Auth.APIKeyIn = *apiKeyIn
	}
	if *failOn != "" {
		cfg.Reporter.FailOn = core.Severity(*failOn)
	}
	if *baseline != "" {
		cfg.Reporter.BaselineFile = *baseline
	}
	if *outputDir != "" {
		cfg.Reporter.OutputDir = *outputDir
	}
	if *timeout > 0 {
		cfg.Timeout = *timeout
	}
	if *format != "" {
		formats := strings.Split(*format, ",")
		cfg.Reporter.OutputFormats = formats
		cfg.Reporter.Terminal = false
		cfg.Reporter.JSON = false
		cfg.Reporter.HTML = false
		cfg.Reporter.SARIF = false
		for _, f := range formats {
			switch strings.TrimSpace(f) {
			case "terminal":
				cfg.Reporter.Terminal = true
			case "json":
				cfg.Reporter.JSON = true
			case "html":
				cfg.Reporter.HTML = true
			case "sarif":
				cfg.Reporter.SARIF = true
			}
		}
	}

	if err := config.ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return runFuzz(cfg, *rulesPath, *exportGraph)
}

func runAuditCommand() int {
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)

	var (
		specPath            = auditCmd.String("spec", "", "Path to OpenAPI spec file (JSON/YAML)")
		policyPath          = auditCmd.String("policy", "", "Path to compliance policy YAML file")
		severityThreshold   = auditCmd.String("severity-threshold", "medium", "Minimum severity to report: critical,high,medium,low,info")
		outputDir           = auditCmd.String("output", "./audit-reports", "Output directory for audit reports")
		format              = auditCmd.String("format", "terminal,json", "Report formats: terminal,json,html (comma-separated)")
		enableDynamic       = auditCmd.Bool("dynamic", false, "Enable dynamic probing (requires --url)")
		targetURL           = auditCmd.String("url", "", "Target API base URL for dynamic probing")
		categories          = auditCmd.String("categories", "", "Only check specified categories (comma-separated): auth,data-exposure,input-validation,rate-limit,versioning,error-handling,cors,security-headers,info-leak,http-methods,content-type")
		baseline            = auditCmd.String("baseline", "", "Path to previous audit report for comparison")
		authType            = auditCmd.String("auth-type", "", "Authentication type: bearer,apikey,basic,oauth2")
		token               = auditCmd.String("token", "", "Bearer token for dynamic probing")
		apiKey              = auditCmd.String("api-key", "", "API key for dynamic probing")
		apiKeyName          = auditCmd.String("api-key-name", "X-API-Key", "API key header/query name")
		apiKeyIn            = auditCmd.String("api-key-in", "header", "API key location: header,query,cookie")
		qps                 = auditCmd.Int("qps", 10, "Queries per second limit for dynamic probing")
		concurrency         = auditCmd.Int("concurrency", 5, "Concurrent requests limit for dynamic probing")
		fix                 = auditCmd.Bool("fix", false, "Enable fix mode: show available patches after audit")
		fixAll              = auditCmd.Bool("fix-all", false, "Auto-apply all valid patches to spec file (outputs .fixed.yaml)")
		fixRules            = auditCmd.String("fix-rules", "", "Only apply patches for specified rule IDs (comma-separated, e.g. ERROR-001,INPUT-002)")
		exportPatches       = auditCmd.Bool("export-patches", false, "Export all patches to patches/ directory")
		exportPatchesFormat = auditCmd.String("export-patches-format", "jsonpatch", "Export format: jsonpatch (RFC 6902), mergepatch (RFC 7396), yaml-diff")
		help                = auditCmd.Bool("help", false, "Show help for audit command")
	)

	auditCmd.Parse(os.Args[1:])

	if *help {
		fmt.Println(`Audit Command - Run API compliance audit

Usage:
  apifuzzer audit --spec <path> [flags]

Flags:
  --spec <path>              Path to OpenAPI spec file (JSON/YAML) [required]
  --policy <path>            Path to compliance policy YAML file (default: built-in OWASP API Top 10)
  --severity-threshold <sev> Minimum severity to report (default: medium)
  --output <dir>             Output directory for audit reports (default: ./audit-reports)
  --format <formats>         Report formats: terminal,json,html (comma-separated)
  --dynamic                  Enable dynamic probing (requires --url)
  --url <url>                Target API base URL for dynamic probing
  --categories <cats>        Only check specified categories (comma-separated)
  --baseline <path>          Path to previous audit report for comparison
  --auth-type <type>         Authentication type for dynamic probing
  --token <token>            Bearer token for dynamic probing
  --api-key <key>            API key for dynamic probing
  --api-key-name <name>      API key header/query name (default: X-API-Key)
  --api-key-in <loc>         API key location: header,query,cookie (default: header)
  --qps <int>                Queries per second limit for dynamic probing (default: 10)
  --concurrency <int>        Concurrent requests limit for dynamic probing (default: 5)
  --fix                      Enable fix mode: show available patches after audit
  --fix-all                  Auto-apply all valid patches (outputs .fixed.yaml)
  --fix-rules <ids>          Only apply patches for specified rule IDs (comma-separated)
  --export-patches           Export all patches to patches/ directory
  --export-patches-format <f> Export format: jsonpatch, mergepatch, yaml-diff (default: jsonpatch)
  --help                     Show this help message

Categories:
  auth, data-exposure, input-validation, rate-limit, versioning,
  error-handling, cors, security-headers, info-leak, http-methods, content-type

Patch Generation Rules:
  ERROR-001  Add standard 4xx error responses (400, 401, 403, 404)
  ERROR-002  Add standard 5xx error response (500)
  INPUT-002  Add maxLength constraint to string parameters
  INPUT-003  Add minimum/maximum constraints to numeric parameters
  DATA-003   Add limit and offset pagination parameters
  VERSION-001 Add /v1 version prefix to API paths
  AUTH-002/003 Add Bearer authentication security requirements`)
		return 0
	}

	if *specPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --spec is required for audit command")
		return 1
	}

	auditConfig := audit.DefaultAuditConfig()
	auditConfig.SpecPath = *specPath
	auditConfig.PolicyPath = *policyPath
	auditConfig.SeverityThreshold = core.Severity(*severityThreshold)
	auditConfig.OutputDir = *outputDir
	auditConfig.EnableDynamic = *enableDynamic
	auditConfig.TargetURL = *targetURL
	auditConfig.BaselineFile = *baseline

	if *categories != "" {
		cats := strings.Split(*categories, ",")
		for _, c := range cats {
			auditConfig.Categories = append(auditConfig.Categories, strings.TrimSpace(c))
		}
	}

	if *format != "" {
		formats := strings.Split(*format, ",")
		auditConfig.OutputFormats = formats
		auditConfig.Terminal = false
		auditConfig.JSON = false
		auditConfig.HTML = false
		for _, f := range formats {
			switch strings.TrimSpace(f) {
			case "terminal":
				auditConfig.Terminal = true
			case "json":
				auditConfig.JSON = true
			case "html":
				auditConfig.HTML = true
			}
		}
	}

	if *authType != "" {
		auditConfig.Auth.Type = *authType
	}
	if *token != "" {
		auditConfig.Auth.BearerToken = *token
	}
	if *apiKey != "" {
		auditConfig.Auth.APIKey = *apiKey
	}
	if *apiKeyName != "" {
		auditConfig.Auth.APIKeyName = *apiKeyName
	}
	if *apiKeyIn != "" {
		auditConfig.Auth.APIKeyIn = *apiKeyIn
	}
	if *qps > 0 {
		auditConfig.RateLimit.QPS = *qps
	}
	if *concurrency > 0 {
		auditConfig.RateLimit.Concurrency = *concurrency
	}

	auditConfig.Fix = *fix
	auditConfig.FixAll = *fixAll
	auditConfig.FixRules = *fixRules
	auditConfig.ExportPatches = *exportPatches
	auditConfig.ExportPatchesFormat = *exportPatchesFormat

	validFormats := map[string]bool{
		"jsonpatch":  true,
		"mergepatch": true,
		"yaml-diff":  true,
	}
	if *exportPatchesFormat != "" && !validFormats[*exportPatchesFormat] {
		fmt.Fprintf(os.Stderr, "Error: invalid export-patches-format: %s (supported: jsonpatch, mergepatch, yaml-diff)\n", *exportPatchesFormat)
		return 1
	}

	if (*fix || *fixAll || *fixRules != "") && *specPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --spec is required when using fix options")
		return 1
	}

	validSeverities := map[core.Severity]bool{
		core.SeverityCritical: true,
		core.SeverityHigh:     true,
		core.SeverityMedium:   true,
		core.SeverityLow:      true,
		core.SeverityInfo:     true,
	}
	if !validSeverities[auditConfig.SeverityThreshold] {
		fmt.Fprintf(os.Stderr, "Error: invalid severity threshold: %s\n", auditConfig.SeverityThreshold)
		return 1
	}

	if *enableDynamic && *targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --url is required when --dynamic is enabled")
		return 1
	}

	report, err := audit.RunAudit(auditConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Audit failed: %v\n", err)
		return 1
	}

	exitCode := 0
	threshold := severityOrder(auditConfig.SeverityThreshold)
	for _, finding := range report.Findings {
		if severityOrder(finding.Severity) >= threshold {
			exitCode = 1
			break
		}
	}

	if exitCode != 0 {
		fmt.Printf("\n❌ Audit found issues exceeding threshold (%s). Exiting with code %d\n",
			auditConfig.SeverityThreshold, exitCode)
	} else {
		fmt.Println("\n✅ All compliance checks passed!")
	}

	return exitCode
}

func runAllCommand() int {
	allCmd := flag.NewFlagSet("all", flag.ExitOnError)

	var (
		specPath    = allCmd.String("spec", "", "Path to OpenAPI spec file (JSON/YAML)")
		targetURL   = allCmd.String("url", "", "Target API base URL")
		configPath  = allCmd.String("config", "", "Path to YAML configuration file")
		seed        = allCmd.Int64("seed", 0, "Random seed for reproducible tests")
		qps         = allCmd.Int("qps", 10, "Queries per second limit")
		concurrency = allCmd.Int("concurrency", 5, "Concurrent requests limit")
		authType    = allCmd.String("auth-type", "", "Authentication type: bearer,apikey,basic,oauth2")
		token       = allCmd.String("token", "", "Bearer token")
		apiKey      = allCmd.String("api-key", "", "API key")
		apiKeyName  = allCmd.String("api-key-name", "X-API-Key", "API key header/query name")
		apiKeyIn    = allCmd.String("api-key-in", "header", "API key location: header,query,cookie")
		timeout     = allCmd.Duration("timeout", 60*time.Minute, "Overall scan timeout")
		fuzzOutput  = allCmd.String("fuzz-output", "./reports", "Output directory for fuzz reports")
		auditOutput = allCmd.String("audit-output", "./audit-reports", "Output directory for audit reports")
		format      = allCmd.String("format", "terminal,json", "Output formats (comma-separated)")
		help        = allCmd.Bool("help", false, "Show help for all command")
	)

	allCmd.Parse(os.Args[1:])

	if *help {
		fmt.Println(`All Command - Run both fuzzing and audit

Usage:
  apifuzzer all --spec <path> --url <url> [flags]

Flags:
  --spec <path>         Path to OpenAPI spec file (JSON/YAML) [required]
  --url <url>           Target API base URL [required]
  --config <path>       Path to YAML configuration file
  --seed <int>          Random seed for reproducible tests
  --qps <int>           Queries per second limit (default: 10)
  --concurrency <int>   Concurrent requests limit (default: 5)
  --auth-type <type>    Authentication type
  --token <token>       Bearer token
  --api-key <key>       API key
  --api-key-name <name> API key header/query name
  --api-key-in <loc>    API key location
  --timeout <duration>  Overall scan timeout (default: 60m)
  --fuzz-output <dir>   Output directory for fuzz reports (default: ./reports)
  --audit-output <dir>  Output directory for audit reports (default: ./audit-reports)
  --format <formats>    Output formats (comma-separated)
  --help                Show this help message`)
		return 0
	}

	if *specPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --spec is required for all command")
		return 1
	}
	if *targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --url is required for all command")
		return 1
	}

	fmt.Println("🚀 Running comprehensive API security scan (fuzzing + audit)...")
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println()

	auditConfig := audit.DefaultAuditConfig()
	auditConfig.SpecPath = *specPath
	auditConfig.TargetURL = *targetURL
	auditConfig.EnableDynamic = true
	auditConfig.OutputDir = *auditOutput
	auditConfig.Auth.Type = *authType
	auditConfig.Auth.BearerToken = *token
	auditConfig.Auth.APIKey = *apiKey
	auditConfig.Auth.APIKeyName = *apiKeyName
	auditConfig.Auth.APIKeyIn = *apiKeyIn
	auditConfig.RateLimit.QPS = *qps
	auditConfig.RateLimit.Concurrency = *concurrency

	if *format != "" {
		formats := strings.Split(*format, ",")
		auditConfig.OutputFormats = formats
		auditConfig.Terminal = false
		auditConfig.JSON = false
		auditConfig.HTML = false
		for _, f := range formats {
			switch strings.TrimSpace(f) {
			case "terminal":
				auditConfig.Terminal = true
			case "json":
				auditConfig.JSON = true
			case "html":
				auditConfig.HTML = true
			}
		}
	}

	fmt.Println("📋 Phase 1: Compliance Audit")
	fmt.Println(strings.Repeat("─", 80))
	auditReport, auditErr := audit.RunAudit(auditConfig)

	fmt.Println()
	fmt.Println("🧪 Phase 2: API Fuzzing")
	fmt.Println(strings.Repeat("─", 80))

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return 1
	}

	cfg.OpenAPISpec = *specPath
	cfg.TargetURL = *targetURL
	cfg.Fuzz.Seed = *seed
	cfg.RateLimit.QPS = *qps
	cfg.RateLimit.Concurrency = *concurrency
	cfg.Auth.Type = *authType
	cfg.Auth.BearerToken = *token
	cfg.Auth.APIKey = *apiKey
	cfg.Auth.APIKeyName = *apiKeyName
	cfg.Auth.APIKeyIn = *apiKeyIn
	cfg.Timeout = *timeout
	cfg.Reporter.OutputDir = *fuzzOutput

	if *format != "" {
		formats := strings.Split(*format, ",")
		cfg.Reporter.OutputFormats = formats
		cfg.Reporter.Terminal = false
		cfg.Reporter.JSON = false
		cfg.Reporter.HTML = false
		cfg.Reporter.SARIF = false
		for _, f := range formats {
			switch strings.TrimSpace(f) {
			case "terminal":
				cfg.Reporter.Terminal = true
			case "json":
				cfg.Reporter.JSON = true
			case "html":
				cfg.Reporter.HTML = true
			case "sarif":
				cfg.Reporter.SARIF = true
			}
		}
	}

	if err := config.ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	fuzzExitCode := runFuzz(cfg, "", "")

	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println("📊 Comprehensive Scan Summary")
	fmt.Println(strings.Repeat("─", 80))

	exitCode := 0
	if auditErr != nil {
		fmt.Printf("❌ Audit: Failed - %v\n", auditErr)
		exitCode = 1
	} else if auditReport != nil {
		fmt.Printf("✅ Audit: Compliance Score %.1f/100, %d findings\n",
			auditReport.ComplianceScore, len(auditReport.Findings))
		for _, finding := range auditReport.Findings {
			if severityOrder(finding.Severity) >= severityOrder(core.SeverityHigh) {
				exitCode = 1
			}
		}
	}

	if fuzzExitCode != 0 {
		fmt.Println("❌ Fuzzing: Found high-severity issues")
		exitCode = 1
	} else {
		fmt.Println("✅ Fuzzing: All checks passed")
	}

	fmt.Println()
	if exitCode != 0 {
		fmt.Printf("❌ Comprehensive scan completed with issues. Exiting with code %d\n", exitCode)
	} else {
		fmt.Println("✅ Comprehensive scan completed successfully!")
	}

	return exitCode
}

func severityOrder(sev core.Severity) int {
	switch sev {
	case core.SeverityCritical:
		return 5
	case core.SeverityHigh:
		return 4
	case core.SeverityMedium:
		return 3
	case core.SeverityLow:
		return 2
	case core.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func runFuzz(cfg *core.Config, rulesPath, exportGraph string) int {
	var initMessages []string

	logStep := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if cfg.Interactive {
			initMessages = append(initMessages, msg)
		} else {
			fmt.Println(msg)
		}
	}

	logStep("🔍 API Fuzzer v%s starting...", version)
	logStep("📄 OpenAPI Spec: %s", cfg.OpenAPISpec)
	logStep("🎯 Target URL: %s", cfg.TargetURL)
	logStep("🌱 Seed: %d", cfg.Fuzz.Seed)

	logStep("Parsing OpenAPI specification...")
	api, err := openapi.ParseOpenAPI(cfg.OpenAPISpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to parse OpenAPI spec: %v\n", err)
		return 1
	}

	if cfg.TargetURL == "" && len(api.Servers) > 0 {
		cfg.TargetURL = api.Servers[0].URL
		logStep("ℹ️  Using server URL from spec: %s", cfg.TargetURL)
	}

	if cfg.TargetURL == "" {
		fmt.Fprintln(os.Stderr, "❌ No target URL specified. Use --url or define servers in OpenAPI spec")
		return 1
	}

	if _, err := url.Parse(cfg.TargetURL); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Invalid target URL: %v\n", err)
		return 1
	}

	totalEndpoints := 0
	for _, methods := range api.Paths {
		totalEndpoints += len(methods)
	}
	logStep("✅ Found %d endpoints across %d paths", totalEndpoints, len(api.Paths))

	logStep("🏥 Performing health check...")
	if err := openapi.CheckHealth(cfg.TargetURL, 10*time.Second); err != nil {
		logStep("⚠️  Health check warning: %v", err)
	} else {
		logStep("✅ Target service is reachable")
	}

	ruleEngine := rules.NewRuleEngine(cfg.Fuzz.Seed)
	if rulesPath != "" {
		logStep("📜 Loading custom rules...")
		if err := ruleEngine.LoadFromFile(rulesPath); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to load rules: %v\n", err)
			return 1
		}
		ruleEngine.MergeIntoFuzzConfig(&cfg.Fuzz)
		logStep("✅ Custom rules loaded")
	}

	specHash, _ := checkpoint.ComputeFileHash(cfg.OpenAPISpec)

	var checkpointData *core.CheckpointData
	var completedTestIDs map[string]bool
	if cfg.ResumeFile != "" {
		logStep("⏳ Loading checkpoint from: %s", cfg.ResumeFile)
		ckptMgr := checkpoint.NewManager(cfg.ResumeFile)
		checkpointData, err = ckptMgr.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to load checkpoint: %v\n", err)
			return 1
		}

		compat := checkpoint.CheckCompatibility(checkpointData, api, cfg.TargetURL)
		if !compat.IsCompatible {
			fmt.Fprintf(os.Stderr, "❌ Checkpoint incompatible:\n")
			for _, msg := range compat.Messages {
				fmt.Fprintf(os.Stderr, "   - %s\n", msg)
			}
			return 1
		}
		if compat.HasChanges {
			logStep("⚠️  Detected spec changes:")
			for _, msg := range compat.Messages {
				logStep("   - %s", msg)
			}
		}

		completedTestIDs = make(map[string]bool)
		for _, id := range checkpointData.CompletedTestIDs {
			completedTestIDs[id] = true
		}
		logStep("✅ Checkpoint loaded: %d completed tests, %d issues found",
			len(completedTestIDs), len(checkpointData.Issues))
	}

	logStep("🧪 Initializing scheduler...")
	sched := scheduler.NewScheduler(api, cfg.RateLimit.QPS)
	if checkpointData != nil && checkpointData.SchedulerState != nil {
		sched.RestoreState(checkpointData.SchedulerState)
	}
	logStep("✅ Smart scheduler initialized")

	logStep("🧪 Generating test cases...")
	gen := fuzzer.NewGenerator(cfg.Fuzz.Seed, cfg.Fuzz)

	var allTestCases []*core.TestCase
	statelessCases, err := gen.GenerateTestCases(api, cfg.TargetURL, cfg.Fuzz)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to generate test cases: %v\n", err)
		return 1
	}
	allTestCases = append(allTestCases, statelessCases...)

	var statefulFuzzer *stateful.StatefulFuzzer
	if cfg.Fuzz.Stateful {
		statefulFuzzer = stateful.NewStatefulFuzzer(api, cfg.Fuzz.Seed, cfg.Fuzz)
		statefulCases := statefulFuzzer.GenerateStatefulTestCases()
		allTestCases = append(allTestCases, statefulCases...)
		logStep("✅ Generated %d stateful test cases (CRUD chains)", len(statefulCases))

		if exportGraph != "" {
			graph := statefulFuzzer.GetDependencyGraph()
			dotContent := graph.ToDOT()
			if err := os.WriteFile(exportGraph, []byte(dotContent), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to export dependency graph: %v\n", err)
			} else {
				logStep("📊 Dependency graph exported to: %s", exportGraph)
			}
		}
	}

	if completedTestIDs != nil {
		remaining := make([]*core.TestCase, 0, len(allTestCases))
		for _, tc := range allTestCases {
			if !completedTestIDs[tc.ID] {
				remaining = append(remaining, tc)
			}
		}
		logStep("⏭️  Skipped %d completed test cases, %d remaining",
			len(allTestCases)-len(remaining), len(remaining))
		allTestCases = remaining
	}

	logStep("✅ Total test cases to run: %d", len(allTestCases))

	analyzerInstance, err := analyzer.NewAnalyzer(cfg.Analyzer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to create analyzer: %v\n", err)
		return 1
	}

	dedup := deduplicator.NewDeduplicator()
	if cfg.Reporter.BaselineFile != "" {
		logStep("📋 Loading baseline from: %s", cfg.Reporter.BaselineFile)
		if err := dedup.LoadBaseline(cfg.Reporter.BaselineFile); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to load baseline: %v\n", err)
		}
	}

	if checkpointData != nil {
		dedup.Add(checkpointData.Issues)
	}

	executor := ratelimiter.NewRequestExecutor(cfg.RateLimit, cfg.Auth, cfg.Analyzer.MaxResponseBodySize)

	coverage := core.NewCoverage()
	coverage.EndpointsTotal = totalEndpoints
	if checkpointData != nil && checkpointData.CoverageSnapshot != nil {
		for k, v := range checkpointData.CoverageSnapshot.EndpointsTested {
			if v {
				coverage.MarkEndpoint(k)
			}
		}
	}

	stats := reporter.NewScanStats()
	stats.TotalTestCases = len(allTestCases)

	estimator := progress.NewEstimator(len(allTestCases), float64(cfg.RateLimit.QPS), cfg.Timeout)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !cfg.Interactive {
			fmt.Println("\n⚠️  Received interrupt signal, stopping...")
		}
		cancel()
	}()

	ckptMgr := checkpoint.NewManager(".apifuzzer-checkpoint.json")

	var (
		completed             int32
		skipped               int32
		failed                int32
		startTime             = time.Now()
		tuiProgram            *tea.Program
		tuiModel              *tui.TUIModel
		timeoutWarningPrinted int32
	)

	consecutiveTimeouts := int32(0)
	maxConsecutiveTimeouts := int32(cfg.MaxConsecutiveTimeouts)

	if cfg.Interactive {
		initialState := &core.TUIState{
			IsRunning:      true,
			IsPaused:       false,
			CurrentQPS:     float64(cfg.RateLimit.QPS),
			CompletedTests: 0,
			TotalTests:     len(allTestCases),
			Runtime:        0,
			IssueCount:     len(dedup.GetIssues()),
			RecentIssues:   dedup.GetIssues(),
			Coverage:       coverage,
			FocusedPanel:   0,
			InitMessages:   initMessages,
		}
		tuiModel = tui.NewTUIModel(initialState)
		tuiProgram = tea.NewProgram(tuiModel, tea.WithAltScreen())
		tuiModel.SetProgram(tuiProgram)

		go func() {
			if _, err := tuiProgram.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			}
			cancel()
		}()

		go handleTUICommands(tuiModel, sched, dedup)
	} else {
		fmt.Println()
		fmt.Println("🚀 Starting fuzzing...")
		fmt.Println("Press Ctrl+C to stop early")
		fmt.Println(strings.Repeat("─", 80))
	}

	var wg sync.WaitGroup
	resultChan := make(chan *core.TestResult, len(allTestCases))

	semaphore := make(chan struct{}, cfg.RateLimit.Concurrency)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if cfg.Interactive && tuiModel != nil {
				warningText := ""
				if est := estimator.GetEstimate(); est.WillExceedTimeout {
					warningText = fmt.Sprintf("May not finish before timeout (%s left)", progress.FormatDuration(est.EstimatedTimeLeft))
				}

				state := &core.TUIState{
					IsRunning:       true,
					IsPaused:        sched.IsPaused(),
					CurrentQPS:      float64(sched.GetQPS()),
					CompletedTests:  int(atomic.LoadInt32(&completed)),
					TotalTests:      len(allTestCases),
					Runtime:         time.Since(startTime),
					IssueCount:      len(dedup.GetIssues()),
					RecentIssues:    dedup.GetIssues(),
					Coverage:        coverage,
					CurrentEndpoint: sched.GetState().CurrentEndpoint,
					CurrentStrategy: sched.GetState().CurrentStrategy,
					Progress:        estimator.GetEstimate(),
					TimeoutWarning:  warningText,
					InitMessages:    initMessages,
				}
				tuiModel.SendUpdate(state)
			}

			if ckptMgr.ShouldSave() {
				snapshot := checkpoint.CreateSnapshot(
					getCompletedTestIDs(allTestCases, int(atomic.LoadInt32(&completed))),
					coverage,
					dedup.GetIssues(),
					sched.GetState(),
					cfg.Fuzz.Seed+int64(atomic.LoadInt32(&completed)),
					specHash,
					cfg.TargetURL,
					cfg,
				)
				ckptMgr.Save(snapshot)
			}
		}
	}()

	for _, tc := range allTestCases {
		select {
		case <-ctx.Done():
			break
		default:
		}

		for sched.IsPaused() {
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				break
			default:
			}
		}

		if atomic.LoadInt32(&consecutiveTimeouts) >= maxConsecutiveTimeouts {
			if !cfg.Interactive {
				fmt.Printf("\n⚠️  Service appears to be down (%d consecutive timeouts). Pausing...\n", maxConsecutiveTimeouts)
			}
			break
		}

		if statefulFuzzer != nil && !statefulFuzzer.CanRunTestCase(tc) {
			atomic.AddInt32(&skipped, 1)
			stats.Skipped++
			continue
		}

		resolvedTC := tc
		if statefulFuzzer != nil && tc.IsStateful {
			resolvedTC = statefulFuzzer.ResolveTestCase(tc)
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(testCase *core.TestCase, originalTC *core.TestCase) {
			defer wg.Done()
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			testStart := time.Now()
			result := executeTestCase(ctx, testCase, originalTC, cfg, executor, gen, analyzerInstance, statefulFuzzer, coverage, &consecutiveTimeouts)
			resultChan <- result

			estimator.RecordTest(time.Since(testStart))
			atomic.AddInt32(&completed, 1)

			if !cfg.Interactive && atomic.LoadInt32(&completed)%50 == 0 {
				limiterStats := executor.GetLimiter().GetStats()
				est := estimator.GetEstimate()
				fmt.Printf("  Progress: %d/%d | QPS: %.1f | Issues: %d | ETA: %s\r",
					atomic.LoadInt32(&completed),
					len(allTestCases),
					limiterStats["actual_qps"],
					len(dedup.GetIssues()),
					progress.FormatETA(est.ETA),
				)
			}

			if !cfg.Interactive {
				if est := estimator.GetEstimate(); est.WillExceedTimeout {
					if atomic.CompareAndSwapInt32(&timeoutWarningPrinted, 0, 1) {
						fmt.Printf("\n⚠️  Warning: Scan may not complete before timeout (ETA: %s remaining)\n",
							progress.FormatDuration(est.EstimatedTimeLeft))
					}
				}
			}
		}(resolvedTC, tc)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result == nil {
			continue
		}

		if result.IsSkipped {
			atomic.AddInt32(&skipped, 1)
			stats.Skipped++
			continue
		}

		endpointKey := result.TestCase.Operation.Method + " " + result.TestCase.Operation.Path

		if len(result.Issues) > 0 {
			newIssues := dedup.Add(result.Issues)
			stats.AddIssues(newIssues)
			sched.RecordIssue(endpointKey, result.Issues[0])

			if cfg.Interactive && tuiModel != nil {
				for _, issue := range newIssues {
					tuiModel.SendIssue(issue)
				}
			}
		} else {
			sched.RecordSuccess(endpointKey)
		}

		if !result.IsSuccess {
			atomic.AddInt32(&failed, 1)
			stats.Failed++
		}

		stats.Completed++
	}

	if cfg.Interactive && tuiProgram != nil {
		tuiProgram.Quit()
	}

	if !cfg.Interactive {
		fmt.Println("\n" + strings.Repeat("─", 80))
		fmt.Println("✅ Fuzzing complete!")
	}

	issues := dedup.GetIssues()
	stats.Completed = int(atomic.LoadInt32(&completed))
	stats.Skipped = int(atomic.LoadInt32(&skipped))
	stats.Failed = int(atomic.LoadInt32(&failed))

	if !cfg.Interactive {
		fmt.Println("\n📊 Generating reports...")
	}
	rep := reporter.NewReporter(cfg.Reporter)
	report := &reporter.Report{
		StartTime: startTime,
		EndTime:   time.Now(),
		Duration:  time.Since(startTime),
		Issues:    issues,
		Coverage:  coverage,
		Stats:     stats,
		Config:    cfg,
		TargetURL: cfg.TargetURL,
		APITitle:  api.Title,
		Seed:      cfg.Fuzz.Seed,
	}

	if statefulFuzzer != nil {
		report.DependencyDOT = statefulFuzzer.GetDependencyGraph().ToDOT()
	}

	if err := rep.Generate(report); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to generate reports: %v\n", err)
		return 1
	}

	if !cfg.Interactive {
		fmt.Printf("\n📁 Reports saved to: %s\n", cfg.Reporter.OutputDir)
	}

	ckptMgr.Delete()

	exitCode := 0
	for _, issue := range issues {
		if analyzer.CheckSeverityThreshold(issue.Severity, cfg.Reporter.FailOn) {
			exitCode = 1
			break
		}
	}

	if !cfg.Interactive {
		if exitCode != 0 {
			fmt.Printf("\n❌ Scan found issues exceeding threshold (%s). Exiting with code %d\n", cfg.Reporter.FailOn, exitCode)
		} else {
			fmt.Println("\n✅ All checks passed!")
		}
	}

	return exitCode
}

func handleTUICommands(model *tui.TUIModel, sched *scheduler.Scheduler, dedup *deduplicator.Deduplicator) {
	for cmd := range model.GetCommandChan() {
		switch cmd.(type) {
		case tui.PauseMsg:
			if sched.IsPaused() {
				sched.Resume()
			} else {
				sched.Pause()
			}
		case tui.SkipMsg:
			sched.SkipCurrent()
		case tui.QPSUpMsg:
			sched.SetQPS(sched.GetQPS() + 5)
		case tui.QPSDownMsg:
			sched.SetQPS(sched.GetQPS() - 5)
		case tui.ExportMsg:
			issues := dedup.GetIssues()
			filename := fmt.Sprintf("issues-snapshot-%d.json", time.Now().Unix())
			checkpoint.ExportIssuesSnapshot(issues, filename)
			fmt.Printf("📤 Issues exported to: %s\n", filename)
		}
	}
}

func getCompletedTestIDs(allTestCases []*core.TestCase, completed int) []string {
	ids := make([]string, 0, completed)
	for i := 0; i < completed && i < len(allTestCases); i++ {
		ids = append(ids, allTestCases[i].ID)
	}
	return ids
}

func executeTestCase(
	ctx context.Context,
	tc *core.TestCase,
	originalTC *core.TestCase,
	cfg *core.Config,
	executor *ratelimiter.RequestExecutor,
	gen *fuzzer.Generator,
	analyzerInstance *analyzer.Analyzer,
	statefulFuzzer *stateful.StatefulFuzzer,
	coverage *core.Coverage,
	consecutiveTimeouts *int32,
) *core.TestResult {
	result := &core.TestResult{
		TestCase:   originalTC,
		IsSuccess:  true,
	}

	bodyStr, err := fuzzer.MarshalBody(tc.Body)
	if err != nil {
		result.IsSuccess = false
		return result
	}

	fullURL := fuzzer.BuildURL(cfg.TargetURL, tc.Operation.Path, tc.PathParams, tc.QueryParams)

	req := &core.HTTPRequest{
		Method:      tc.Operation.Method,
		URL:         fullURL,
		Headers:     make(map[string]string),
		Cookies:     make(map[string]string),
		Body:        bodyStr,
		ContentType: tc.ContentType,
	}

	for k, v := range tc.HeaderParams {
		req.Headers[k] = core.ToString(v)
	}
	for k, v := range tc.CookieParams {
		req.Cookies[k] = core.ToString(v)
	}

	result.Request = req

	coverage.MarkEndpoint(tc.Operation.Path)
	coverage.MarkMethod(tc.Operation.Path, tc.Operation.Method)

	for name := range tc.QueryParams {
		coverage.MarkParam(tc.Operation.Path, name, "query")
	}
	for name := range tc.PathParams {
		coverage.MarkParam(tc.Operation.Path, name, "path")
	}

	resp, err := executor.Execute(ctx, req)
	if err != nil {
		result.IsSuccess = false
		if ctx.Err() == context.DeadlineExceeded {
			result.IsSkipped = true
			result.SkipReason = "timeout"
		}
		result.Response = &core.HTTPResponse{
			Error: err,
		}
		atomic.AddInt32(consecutiveTimeouts, 1)
		return result
	}

	result.Response = resp
	atomic.StoreInt32(consecutiveTimeouts, 0)

	coverage.MarkResponseCode(tc.Operation.Path, resp.StatusCode)

	if statefulFuzzer != nil && originalTC.IsStateful {
		statefulFuzzer.HandleTestResult(originalTC, resp)
	}

	issues := analyzerInstance.Analyze(originalTC, req, resp)
	result.Issues = issues

	if len(issues) > 0 {
		result.IsSuccess = false
	}

	return result
}

func saveCoverageJSON(coverage *core.Coverage, outputDir string) {
	data := map[string]interface{}{
		"endpoint_coverage": coverage.EndpointCoverage(),
		"endpoints_tested":  coverage.EndpointsTested,
		"endpoints_total":   coverage.EndpointsTotal,
		"methods_tested":    coverage.MethodsTested,
		"response_codes":    coverage.ResponseCodes,
		"params_tested":     coverage.ParamsTested,
	}

	filePath := outputDir + "/coverage.json"
	jsonData, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(filePath, jsonData, 0644)
}
