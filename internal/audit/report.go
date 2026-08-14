package audit

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

const (
	auditColorReset   = "\033[0m"
	auditColorRed     = "\033[31m"
	auditColorGreen   = "\033[32m"
	auditColorYellow  = "\033[33m"
	auditColorBlue    = "\033[34m"
	auditColorMagenta = "\033[35m"
	auditColorCyan    = "\033[36m"
	auditColorBold    = "\033[1m"
)

type AuditReporter struct {
	config core.AuditConfig
}

func NewAuditReporter(config core.AuditConfig) *AuditReporter {
	return &AuditReporter{config: config}
}

func CalculateComplianceScore(findings []*core.AuditFinding, totalRules int) float64 {
	if totalRules == 0 {
		return 100.0
	}

	severityWeights := map[core.Severity]float64{
		core.SeverityCritical: 10.0,
		core.SeverityHigh:     5.0,
		core.SeverityMedium:   2.0,
		core.SeverityLow:      0.5,
		core.SeverityInfo:     0.1,
	}

	totalPenalty := 0.0
	ruleFindings := make(map[string]bool)
	for _, f := range findings {
		if !ruleFindings[f.RuleID] {
			ruleFindings[f.RuleID] = true
			weight := severityWeights[f.Severity]
			totalPenalty += weight
		}
	}

	maxPossiblePenalty := float64(totalRules) * 10.0
	score := 100.0 - (totalPenalty / maxPossiblePenalty * 100.0)
	if score < 0 {
		score = 0
	}
	return score
}

func ComputeStats(findings []*core.AuditFinding, totalRules int) *core.AuditStats {
	stats := &core.AuditStats{
		TotalRules:  totalRules,
		BySeverity:  make(map[core.Severity]int),
		ByCategory:  make(map[string]int),
	}

	failedRules := make(map[string]bool)
	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[f.RuleCategory]++
		failedRules[f.RuleID] = true
	}

	stats.FailedRules = len(failedRules)
	stats.PassedRules = totalRules - stats.FailedRules
	stats.ComplianceScore = CalculateComplianceScore(findings, totalRules)

	return stats
}

func CompareWithBaseline(currentFindings []*core.AuditFinding, baselinePath string) (*core.AuditBaselineDiff, error) {
	if baselinePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baselineReport struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
			RuleID      string `json:"rule_id"`
		} `json:"findings"`
	}

	if err := json.Unmarshal(data, &baselineReport); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	baselineFingerprints := make(map[string]bool)
	for _, f := range baselineReport.Findings {
		baselineFingerprints[f.Fingerprint] = true
	}

	diff := &core.AuditBaselineDiff{
		NewFindings:      make([]*core.AuditFinding, 0),
		FixedFindings:    make([]*core.AuditFinding, 0),
		ExistingFindings: make([]*core.AuditFinding, 0),
	}

	currentFingerprints := make(map[string]*core.AuditFinding)
	for _, f := range currentFindings {
		currentFingerprints[f.Fingerprint] = f
		if baselineFingerprints[f.Fingerprint] {
			diff.ExistingFindings = append(diff.ExistingFindings, f)
		} else {
			diff.NewFindings = append(diff.NewFindings, f)
		}
	}

	for fp := range baselineFingerprints {
		if _, exists := currentFingerprints[fp]; !exists {
			diff.FixedFindings = append(diff.FixedFindings, &core.AuditFinding{Fingerprint: fp})
		}
	}

	return diff, nil
}

func (r *AuditReporter) Generate(report *core.AuditReport) error {
	if err := os.MkdirAll(r.config.OutputDir, 0755); err != nil {
		return err
	}

	if r.config.Terminal {
		r.printTerminal(report)
	}

	if r.config.JSON {
		if err := r.writeJSON(report); err != nil {
			return err
		}
	}

	if r.config.HTML {
		if err := r.writeHTML(report); err != nil {
			return err
		}
	}

	return nil
}

func (r *AuditReporter) printTerminal(report *core.AuditReport) {
	fmt.Println()
	fmt.Println(auditColorBold + auditColorCyan + "╔════════════════════════════════════════════════════════════╗" + auditColorReset)
	fmt.Println(auditColorBold + auditColorCyan + "║                  API Compliance Audit                      ║" + auditColorReset)
	fmt.Println(auditColorBold + auditColorCyan + "╚════════════════════════════════════════════════════════════╝" + auditColorReset)
	fmt.Println()

	scoreColor := auditColorGreen
	if report.ComplianceScore < 70 {
		scoreColor = auditColorRed
	} else if report.ComplianceScore < 90 {
		scoreColor = auditColorYellow
	}

	fmt.Printf(auditColorBold+"Compliance Score: "+auditColorReset+"%s%.1f/100"+auditColorReset+"\n", scoreColor, report.ComplianceScore)
	fmt.Printf(auditColorBold+"API Title: "+auditColorReset+"%s\n", report.APITitle)
	fmt.Printf(auditColorBold+"Target URL: "+auditColorReset+"%s\n", report.TargetURL)
	fmt.Printf(auditColorBold+"Policy File: "+auditColorReset+"%s\n", report.PolicyFile)
	fmt.Printf(auditColorBold+"Scan Duration: "+auditColorReset+"%s\n", report.Duration.Round(time.Second))
	fmt.Printf(auditColorBold+"Dynamic Probing: "+auditColorReset+"%t\n", r.config.EnableDynamic)
	fmt.Println()

	if report.Stats != nil {
		fmt.Printf(auditColorBold+"Rules Checked: "+auditColorReset+"%d passed, %d failed\n",
			report.Stats.PassedRules, report.Stats.FailedRules)
		fmt.Println()
	}

	if report.BaselineDiff != nil {
		fmt.Println(auditColorBold + "Baseline Comparison:" + auditColorReset)
		fmt.Println(strings.Repeat("─", 60))
		fmt.Printf("  %sNew Issues: "+auditColorReset+"%d\n", auditColorRed, len(report.BaselineDiff.NewFindings))
		fmt.Printf("  %sFixed Issues: "+auditColorReset+"%d\n", auditColorGreen, len(report.BaselineDiff.FixedFindings))
		fmt.Printf("  %sExisting Issues: "+auditColorReset+"%d\n", auditColorYellow, len(report.BaselineDiff.ExistingFindings))
		fmt.Println()
	}

	fmt.Println(auditColorBold + "Findings:" + auditColorReset)
	fmt.Println(strings.Repeat("─", 80))

	severityOrder := []core.Severity{
		core.SeverityCritical,
		core.SeverityHigh,
		core.SeverityMedium,
		core.SeverityLow,
		core.SeverityInfo,
	}

	severityColors := map[core.Severity]string{
		core.SeverityCritical: auditColorRed + auditColorBold,
		core.SeverityHigh:     auditColorRed,
		core.SeverityMedium:   auditColorYellow,
		core.SeverityLow:      auditColorBlue,
		core.SeverityInfo:     auditColorGreen,
	}

	severityLabels := map[core.Severity]string{
		core.SeverityCritical: "CRITICAL",
		core.SeverityHigh:     "HIGH    ",
		core.SeverityMedium:   "MEDIUM  ",
		core.SeverityLow:      "LOW     ",
		core.SeverityInfo:     "INFO    ",
	}

	findingsBySeverity := make(map[core.Severity][]*core.AuditFinding)
	for _, finding := range report.Findings {
		findingsBySeverity[finding.Severity] = append(findingsBySeverity[finding.Severity], finding)
	}

	totalFindings := 0
	for _, sev := range severityOrder {
		findings := findingsBySeverity[sev]
		if len(findings) == 0 {
			continue
		}
		totalFindings += len(findings)

		color := severityColors[sev]
		label := severityLabels[sev]

		fmt.Println()
		fmt.Printf("%s[%s] %d finding(s)"+auditColorReset+"\n", color, label, len(findings))
		fmt.Println(strings.Repeat("─", 80))

		for i, finding := range findings {
			analysisType := "STATIC"
			if !finding.IsStatic {
				analysisType = "DYNAMIC"
			}

			fmt.Printf("%s  %d. [%s] %s"+auditColorReset+"\n", color, i+1, finding.RuleID, finding.Title)
			fmt.Printf("     Category: %s | Type: %s\n", finding.RuleCategory, analysisType)
			if finding.Endpoint != "" {
				fmt.Printf("     Endpoint: %s %s\n", finding.Method, finding.Endpoint)
			}
			fmt.Printf("     Description: %s\n", finding.Description)
			fmt.Printf("     Fix: %s\n", finding.FixSuggestion)

			if i < len(findings)-1 {
				fmt.Println()
			}
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))

	if totalFindings == 0 {
		fmt.Println(auditColorGreen + auditColorBold + "✓ No compliance issues found!" + auditColorReset)
	} else {
		fmt.Printf(auditColorBold+"Total Findings: "+auditColorReset+"%d", totalFindings)
		if report.Stats != nil {
			for _, sev := range severityOrder {
				if count, ok := report.Stats.BySeverity[sev]; ok && count > 0 {
					fmt.Printf(" | %s%s: %d"+auditColorReset, severityColors[sev], strings.TrimSpace(severityLabels[sev]), count)
				}
			}
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println(auditColorCyan + "For detailed reports, see: " + r.config.OutputDir + auditColorReset)
	fmt.Println()
}

func (r *AuditReporter) writeJSON(report *core.AuditReport) error {
	data := map[string]interface{}{
		"version": "1.0",
		"audit_info": map[string]interface{}{
			"start_time":       report.StartTime.Format(time.RFC3339),
			"end_time":         report.EndTime.Format(time.RFC3339),
			"duration_seconds": report.Duration.Seconds(),
			"target_url":       report.TargetURL,
			"api_title":        report.APITitle,
			"policy_file":      report.PolicyFile,
			"dynamic_enabled":  r.config.EnableDynamic,
		},
		"compliance_score": report.ComplianceScore,
		"stats": map[string]interface{}{
			"total_rules":   report.Stats.TotalRules,
			"passed_rules":  report.Stats.PassedRules,
			"failed_rules":  report.Stats.FailedRules,
			"by_severity":   report.Stats.BySeverity,
			"by_category":   report.Stats.ByCategory,
		},
		"findings": r.serializeFindings(report.Findings),
	}

	if report.BaselineDiff != nil {
		data["baseline_diff"] = map[string]interface{}{
			"new_findings":      r.serializeFindings(report.BaselineDiff.NewFindings),
			"fixed_findings":    len(report.BaselineDiff.FixedFindings),
			"existing_findings": r.serializeFindings(report.BaselineDiff.ExistingFindings),
		}
	}

	if r.config.PolicyPath != "" {
		data["policy"] = map[string]interface{}{
			"enabled_rules":        report.Policy.EnabledRules,
			"custom_severities":    report.Policy.CustomSeverities,
			"sensitive_fields":     report.Policy.CustomSensitiveFields,
			"excluded_paths":       report.Policy.ExcludedPaths,
			"custom_rules_count":   len(report.Policy.CustomRules),
		}
	}

	filePath := filepath.Join(r.config.OutputDir, "audit-report.json")
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, jsonData, 0644)
}

func (r *AuditReporter) serializeFindings(findings []*core.AuditFinding) []interface{} {
	var result []interface{}

	for _, finding := range findings {
		findingData := map[string]interface{}{
			"id":             finding.ID,
			"fingerprint":    finding.Fingerprint,
			"rule_id":        finding.RuleID,
			"rule_category":  finding.RuleCategory,
			"severity":       finding.Severity,
			"title":          finding.Title,
			"description":    finding.Description,
			"endpoint":       finding.Endpoint,
			"method":         finding.Method,
			"fix_suggestion": finding.FixSuggestion,
			"is_static":      finding.IsStatic,
			"evidence":       finding.Evidence,
			"created_at":     finding.CreatedAt.Format(time.RFC3339),
		}

		if len(finding.Requests) > 0 {
			req := finding.Requests[0]
			findingData["request"] = map[string]interface{}{
				"method":  req.Method,
				"url":     req.URL,
				"headers": req.Headers,
				"body":    req.Body,
				"curl":    core.ToCurlCommand(req),
			}
		}

		if len(finding.Responses) > 0 {
			resp := finding.Responses[0]
			findingData["response"] = map[string]interface{}{
				"status_code": resp.StatusCode,
				"status":      resp.Status,
				"headers":     resp.Headers,
				"body":        resp.Body,
				"truncated":   resp.BodyTruncated,
			}
		}

		result = append(result, findingData)
	}

	sort.Slice(result, func(i, j int) bool {
		severityOrder := map[core.Severity]int{
			core.SeverityCritical: 5,
			core.SeverityHigh:     4,
			core.SeverityMedium:   3,
			core.SeverityLow:      2,
			core.SeverityInfo:     1,
		}
		fi := findings[i]
		fj := findings[j]
		return severityOrder[fi.Severity] > severityOrder[fj.Severity]
	})

	return result
}

func (r *AuditReporter) writeHTML(report *core.AuditReport) error {
	htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Compliance Audit - {{.APITitle}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; font-size: 28px; }
        
        .score-card { 
            background: linear-gradient(135deg, #0f3460, #16213e); 
            padding: 30px; 
            border-radius: 15px; 
            margin-bottom: 20px;
            text-align: center;
        }
        .score-value { 
            font-size: 72px; 
            font-weight: bold; 
            margin: 10px 0;
        }
        .score-critical { color: #ff4757; }
        .score-warning { color: #ffa502; }
        .score-good { color: #2ed573; }
        
        .summary { background: #16213e; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat-card { background: #0f3460; padding: 15px; border-radius: 8px; }
        .stat-card .label { color: #888; font-size: 12px; text-transform: uppercase; }
        .stat-card .value { font-size: 24px; font-weight: bold; margin-top: 5px; }
        
        .severity-critical { color: #ff4757; }
        .severity-high { color: #ff6b81; }
        .severity-medium { color: #ffa502; }
        .severity-low { color: #70a1ff; }
        .severity-info { color: #7bed9f; }
        
        .filters { 
            background: #16213e; 
            padding: 15px 20px; 
            border-radius: 10px; 
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        .filter-group { display: flex; gap: 10px; align-items: center; }
        .filter-group label { color: #888; font-size: 14px; }
        .filter-group select, .filter-group input {
            background: #0f3460;
            color: #eee;
            border: 1px solid #00d4ff;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .baseline-diff {
            background: #16213e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .diff-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }
        .diff-card { padding: 15px; border-radius: 8px; text-align: center; }
        .diff-new { background: rgba(255, 71, 87, 0.2); border: 1px solid #ff4757; }
        .diff-fixed { background: rgba(46, 213, 115, 0.2); border: 1px solid #2ed573; }
        .diff-existing { background: rgba(255, 165, 2, 0.2); border: 1px solid #ffa502; }
        .diff-value { font-size: 32px; font-weight: bold; margin: 5px 0; }
        
        .findings { margin-top: 30px; }
        .finding { background: #16213e; margin-bottom: 15px; border-radius: 10px; overflow: hidden; }
        .finding-header { 
            padding: 15px 20px; 
            cursor: pointer; 
            display: flex; 
            align-items: center; 
            gap: 15px; 
        }
        .finding-header:hover { background: #0f3460; }
        .severity-badge { 
            padding: 4px 10px; 
            border-radius: 4px; 
            font-size: 12px; 
            font-weight: bold; 
            text-transform: uppercase; 
            min-width: 80px;
            text-align: center;
        }
        .badge-critical { background: #ff4757; color: white; }
        .badge-high { background: #ff6b81; color: white; }
        .badge-medium { background: #ffa502; color: black; }
        .badge-low { background: #70a1ff; color: white; }
        .badge-info { background: #7bed9f; color: black; }
        .badge-static { background: #5352ed; color: white; }
        .badge-dynamic { background: #ff6348; color: white; }
        
        .rule-id { font-family: 'Courier New', monospace; color: #00d4ff; font-size: 13px; min-width: 100px; }
        .finding-title { flex: 1; font-weight: 500; }
        .finding-endpoint { color: #888; font-size: 14px; }
        
        .finding-content { padding: 0 20px; max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }
        .finding-content.open { max-height: 2000px; padding-bottom: 20px; }
        
        .detail-section { margin-top: 15px; }
        .detail-section h4 { color: #00d4ff; margin-bottom: 10px; font-size: 14px; text-transform: uppercase; }
        pre { background: #0a0a1a; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
        code { font-family: 'Courier New', monospace; }
        .evidence-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .evidence-table th, .evidence-table td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; }
        .evidence-table th { color: #00d4ff; }
        
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 API Compliance Audit Report</h1>
        
        <div class="score-card">
            <div style="color: #888; text-transform: uppercase; letter-spacing: 2px;">Compliance Score</div>
            <div class="score-value {{.ScoreClass}}">{{.Score}}</div>
            <div style="color: #888;">Based on {{.TotalRules}} rules checked</div>
        </div>
        
        <div class="summary">
            <h2>Audit Summary</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="label">API Title</div>
                    <div class="value" style="font-size: 16px;">{{.APITitle}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Target URL</div>
                    <div class="value" style="font-size: 16px;">{{.TargetURL}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Duration</div>
                    <div class="value">{{.Duration}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Dynamic Probing</div>
                    <div class="value">{{.DynamicEnabled}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Rules Passed</div>
                    <div class="value severity-info">{{.Stats.PassedRules}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Rules Failed</div>
                    <div class="value severity-critical">{{.Stats.FailedRules}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Critical Issues</div>
                    <div class="value severity-critical">{{SeverityCount .Stats.BySeverity "critical"}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">High Issues</div>
                    <div class="value severity-high">{{SeverityCount .Stats.BySeverity "high"}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Medium Issues</div>
                    <div class="value severity-medium">{{SeverityCount .Stats.BySeverity "medium"}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Low Issues</div>
                    <div class="value severity-low">{{SeverityCount .Stats.BySeverity "low"}}</div>
                </div>
            </div>
        </div>

        {{if .BaselineDiff}}
        <div class="baseline-diff">
            <h2>📊 Baseline Comparison</h2>
            <div class="diff-grid">
                <div class="diff-card diff-new">
                    <div class="label" style="color: #888; text-transform: uppercase; font-size: 12px;">New Issues</div>
                    <div class="diff-value severity-critical">{{len .BaselineDiff.NewFindings}}</div>
                </div>
                <div class="diff-card diff-fixed">
                    <div class="label" style="color: #888; text-transform: uppercase; font-size: 12px;">Fixed Issues</div>
                    <div class="diff-value severity-info">{{len .BaselineDiff.FixedFindings}}</div>
                </div>
                <div class="diff-card diff-existing">
                    <div class="label" style="color: #888; text-transform: uppercase; font-size: 12px;">Existing Issues</div>
                    <div class="diff-value severity-medium">{{len .BaselineDiff.ExistingFindings}}</div>
                </div>
            </div>
        </div>
        {{end}}

        <div class="filters">
            <div class="filter-group">
                <label for="severity-filter">Severity:</label>
                <select id="severity-filter" onchange="filterFindings()">
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="category-filter">Category:</label>
                <select id="category-filter" onchange="filterFindings()">
                    <option value="all">All</option>
                    {{range .Categories}}
                    <option value="{{.}}">{{.}}</option>
                    {{end}}
                </select>
            </div>
            <div class="filter-group">
                <label for="endpoint-filter">Endpoint:</label>
                <input type="text" id="endpoint-filter" placeholder="Search endpoint..." oninput="filterFindings()">
            </div>
            <div class="filter-group">
                <label for="type-filter">Type:</label>
                <select id="type-filter" onchange="filterFindings()">
                    <option value="all">All</option>
                    <option value="static">Static Only</option>
                    <option value="dynamic">Dynamic Only</option>
                </select>
            </div>
        </div>

        <div class="findings">
            <h2>Findings ({{len .Findings}})</h2>
            {{range $i, $f := .Findings}}
            <div class="finding" 
                 data-severity="{{$f.Severity}}" 
                 data-category="{{$f.RuleCategory}}"
                 data-endpoint="{{$f.Endpoint}}"
                 data-type="{{if $f.IsStatic}}static{{else}}dynamic{{end}}">
                <div class="finding-header" onclick="toggleFinding({{$i}})">
                    <span class="severity-badge badge-{{$f.Severity}}">{{$f.Severity}}</span>
                    <span class="severity-badge {{if $f.IsStatic}}badge-static{{else}}badge-dynamic{{end}}">{{if $f.IsStatic}}STATIC{{else}}DYNAMIC{{end}}</span>
                    <span class="rule-id">{{$f.RuleID}}</span>
                    <span class="finding-title">{{$f.Title}}</span>
                    <span class="finding-endpoint">{{if $f.Endpoint}}{{$f.Method}} {{$f.Endpoint}}{{end}}</span>
                    <span style="color: #888;">▼</span>
                </div>
                <div class="finding-content" id="finding-{{$i}}">
                    <div class="detail-section">
                        <h4>Description</h4>
                        <p>{{$f.Description}}</p>
                    </div>
                    {{if $f.Evidence}}
                    <div class="detail-section">
                        <h4>Evidence</h4>
                        <table class="evidence-table">
                            {{range $k, $v := $f.Evidence}}
                            <tr>
                                <th>{{$k}}</th>
                                <td><code>{{$v}}</code></td>
                            </tr>
                            {{end}}
                        </table>
                    </div>
                    {{end}}
                    <div class="detail-section">
                        <h4>Fix Suggestion</h4>
                        <p>{{$f.FixSuggestion}}</p>
                    </div>
                    {{if len $f.Requests}}
                    <div class="detail-section">
                        <h4>Reproduce</h4>
                        <pre><code>{{ToCurl (index $f.Requests 0)}}</code></pre>
                    </div>
                    {{end}}
                    {{if len $f.Responses}}
                    <div class="detail-section">
                        <h4>Response</h4>
                        {{$resp := index $f.Responses 0}}
                        <table class="evidence-table">
                            <tr><th>Status</th><td>{{$resp.StatusCode}} {{$resp.Status}}</td></tr>
                        </table>
                        {{if $resp.Body}}
                        <h4 style="margin-top: 15px;">Response Body</h4>
                        <pre><code>{{$resp.Body}}</code></pre>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
    </div>

    <script>
        function toggleFinding(id) {
            const content = document.getElementById('finding-' + id);
            content.classList.toggle('open');
        }

        function filterFindings() {
            const severity = document.getElementById('severity-filter').value;
            const category = document.getElementById('category-filter').value;
            const endpoint = document.getElementById('endpoint-filter').value.toLowerCase();
            const type = document.getElementById('type-filter').value;

            document.querySelectorAll('.finding').forEach(finding => {
                const fSeverity = finding.dataset.severity;
                const fCategory = finding.dataset.category;
                const fEndpoint = finding.dataset.endpoint.toLowerCase();
                const fType = finding.dataset.type;

                let match = true;

                if (severity !== 'all' && fSeverity !== severity) match = false;
                if (category !== 'all' && fCategory !== category) match = false;
                if (endpoint !== '' && !fEndpoint.includes(endpoint)) match = false;
                if (type !== 'all' && fType !== type) match = false;

                finding.classList.toggle('hidden', !match);
            });

            updateFindingCount();
        }

        function updateFindingCount() {
            const visible = document.querySelectorAll('.finding:not(.hidden)').length;
            document.querySelector('.findings h2').textContent = 'Findings (' + visible + ')';
        }
    </script>
</body>
</html>
`

	type templateData struct {
		APITitle        string
		TargetURL       string
		PolicyFile      string
		Score           string
		ScoreClass      string
		TotalRules      int
		Stats           *core.AuditStats
		Findings        []*core.AuditFinding
		BaselineDiff    *core.AuditBaselineDiff
		Duration        string
		DynamicEnabled  string
		Categories      []string
	}

	score := fmt.Sprintf("%.1f", report.ComplianceScore)
	scoreClass := "score-good"
	if report.ComplianceScore < 70 {
		scoreClass = "score-critical"
	} else if report.ComplianceScore < 90 {
		scoreClass = "score-warning"
	}

	categoriesMap := make(map[string]bool)
	for _, f := range report.Findings {
		categoriesMap[f.RuleCategory] = true
	}
	categories := make([]string, 0, len(categoriesMap))
	for c := range categoriesMap {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	data := templateData{
		APITitle:       report.APITitle,
		TargetURL:      report.TargetURL,
		PolicyFile:     report.PolicyFile,
		Score:          score,
		ScoreClass:     scoreClass,
		TotalRules:     report.Stats.TotalRules,
		Stats:          report.Stats,
		Findings:       report.Findings,
		BaselineDiff:   report.BaselineDiff,
		Duration:       report.Duration.Round(time.Second).String(),
		DynamicEnabled: fmt.Sprintf("%t", r.config.EnableDynamic),
		Categories:     categories,
	}

	funcMap := template.FuncMap{
		"ToCurl": core.ToCurlCommand,
		"SeverityCount": func(bySeverity map[core.Severity]int, sev string) int {
			return bySeverity[core.Severity(sev)]
		},
	}

	tmpl, err := template.New("audit-report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	filePath := filepath.Join(r.config.OutputDir, "audit-report.html")
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}
