package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"github.com/api-fuzzer/apifuzzer/internal/openapi"
)

func RunAudit(auditConfig *core.AuditConfig) (*core.AuditReport, error) {
	startTime := time.Now()

	fmt.Println("🔍 API Compliance Audit starting...")
	fmt.Println("📄 OpenAPI Spec:", auditConfig.SpecPath)

	if auditConfig.EnableDynamic {
		fmt.Println("🎯 Target URL:", auditConfig.TargetURL)
	}

	fmt.Println("📜 Loading compliance policy...")
	policy, err := LoadPolicy(auditConfig.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}
	fmt.Println("✅ Policy loaded successfully")

	fmt.Println("🔍 Parsing OpenAPI specification...")
	api, err := openapi.ParseOpenAPI(auditConfig.SpecPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	if auditConfig.EnableDynamic && auditConfig.TargetURL == "" {
		if len(api.Servers) > 0 {
			auditConfig.TargetURL = api.Servers[0].URL
			fmt.Println("ℹ️  Using server URL from spec:", auditConfig.TargetURL)
		} else {
			return nil, fmt.Errorf("target URL is required for dynamic probing (use --url)")
		}
	}

	totalEndpoints := 0
	for _, methods := range api.Paths {
		totalEndpoints += len(methods)
	}
	fmt.Printf("✅ Found %d endpoints across %d paths\n", totalEndpoints, len(api.Paths))

	allFindings := make([]*core.AuditFinding, 0)

	fmt.Println("\n🔬 Performing static analysis...")
	staticAnalyzer := NewStaticAnalyzer(api, policy, auditConfig)
	staticFindings := staticAnalyzer.Analyze()
	allFindings = append(allFindings, staticFindings...)
	fmt.Printf("✅ Static analysis complete: %d findings\n", len(staticFindings))

	if auditConfig.EnableDynamic {
		fmt.Println("\n🌐 Performing dynamic probing...")

		dynamicProber := NewDynamicProber(api, policy, auditConfig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		dynamicFindings := dynamicProber.Probe(ctx)
		allFindings = append(allFindings, dynamicFindings...)
		fmt.Printf("✅ Dynamic probing complete: %d findings\n", len(dynamicFindings))
	}

	enabledRules := 0
	for _, rule := range BuiltInRules {
		if IsRuleEnabled(rule.ID, policy, auditConfig.Categories) {
			enabledRules++
		}
	}
	for _, cr := range policy.CustomRules {
		if IsRuleEnabled(cr.ID, policy, auditConfig.Categories) {
			enabledRules++
		}
	}

	stats := ComputeStats(allFindings, enabledRules)

	fmt.Println("\n📊 Computing baseline comparison...")
	baselineDiff, err := CompareWithBaseline(allFindings, auditConfig.BaselineFile)
	if err != nil {
		fmt.Printf("⚠️  Warning: Failed to compare with baseline: %v\n", err)
	}

	policyDisplay := auditConfig.PolicyPath
	if policyDisplay == "" {
		policyDisplay = "Built-in OWASP API Top 10 Policy"
	}

	report := &core.AuditReport{
		StartTime:       startTime,
		EndTime:         time.Now(),
		Duration:        time.Since(startTime),
		APITitle:        api.Title,
		TargetURL:       auditConfig.TargetURL,
		PolicyFile:      policyDisplay,
		Findings:        allFindings,
		Stats:           stats,
		Config:          auditConfig,
		Policy:          policy,
		BaselineDiff:    baselineDiff,
		ComplianceScore: stats.ComplianceScore,
	}

	fmt.Println("\n📋 Generating reports...")
	reporter := NewAuditReporter(*auditConfig)
	if err := reporter.Generate(report); err != nil {
		return report, fmt.Errorf("failed to generate reports: %w", err)
	}

	fmt.Printf("\n📁 Reports saved to: %s\n", auditConfig.OutputDir)

	if ShouldRunFix(auditConfig) || auditConfig.ExportPatches {
		fmt.Println("\n🔧 Generating fix patches...")
		patchGen := NewPatchGenerator(api, policy, auditConfig)
		allStaticFindings := staticAnalyzer.GetAllFindings()
		patches := patchGen.GeneratePatches(allStaticFindings)
		fmt.Printf("✅ Generated %d fix patches\n", len(patches))

		if auditConfig.ExportPatches {
			exporter := NewPatchExporter(auditConfig)
			if err := exporter.ExportPatches(patches, auditConfig.OutputDir); err != nil {
				fmt.Printf("⚠️  Warning: Failed to export patches: %v\n", err)
			}
		}

		if ShouldRunFix(auditConfig) {
			if err := RunFixFlow(auditConfig, patches, auditConfig.SpecPath); err != nil {
				fmt.Printf("⚠️  Warning: Fix flow failed: %v\n", err)
			}
		}
	}

	return report, nil
}
