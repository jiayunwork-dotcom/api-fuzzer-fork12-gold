package reporter

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
	colorReset    = "\033[0m"
	colorRed      = "\033[31m"
	colorGreen    = "\033[32m"
	colorYellow   = "\033[33m"
	colorBlue     = "\033[34m"
	colorMagenta  = "\033[35m"
	colorCyan     = "\033[36m"
	colorBold     = "\033[1m"
)

type Report struct {
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
	Issues        []*core.Issue
	Coverage      *core.Coverage
	Stats         *ScanStats
	Config        *core.Config
	DependencyDOT string
	TargetURL     string
	APITitle      string
	Seed          int64
}

type ScanStats struct {
	TotalTestCases int
	Completed      int
	Skipped        int
	Failed         int
	BySeverity     map[core.Severity]int
	ByType         map[core.IssueType]int
}

type Reporter struct {
	config core.ReporterConfig
}

func NewReporter(config core.ReporterConfig) *Reporter {
	return &Reporter{config: config}
}

func (r *Reporter) Generate(report *Report) error {
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

	if r.config.SARIF {
		if err := r.writeSARIF(report); err != nil {
			return err
		}
	}

	return nil
}

func (r *Reporter) printTerminal(report *Report) {
	fmt.Println()
	fmt.Println(colorBold + colorCyan + "╔════════════════════════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorBold + colorCyan + "║                    API Fuzzer Report                       ║" + colorReset)
	fmt.Println(colorBold + colorCyan + "╚════════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()

	fmt.Printf(colorBold+"Target: "+colorReset+"%s\n", report.TargetURL)
	fmt.Printf(colorBold+"API Title: "+colorReset+"%s\n", report.APITitle)
	fmt.Printf(colorBold+"Scan Duration: "+colorReset+"%s\n", report.Duration.Round(time.Second))
	fmt.Printf(colorBold+"Seed: "+colorReset+"%d\n", report.Seed)
	fmt.Printf(colorBold+"Test Cases: "+colorReset+"%d completed, %d skipped, %d failed\n",
		report.Stats.Completed, report.Stats.Skipped, report.Stats.Failed)

	if report.Coverage != nil {
		fmt.Printf(colorBold+"Endpoint Coverage: "+colorReset+"%.1f%%\n", report.Coverage.EndpointCoverage())
	}

	fmt.Println()
	fmt.Println(colorBold + "Issues Found:" + colorReset)
	fmt.Println(strings.Repeat("─", 80))

	severityOrder := []core.Severity{
		core.SeverityCritical,
		core.SeverityHigh,
		core.SeverityMedium,
		core.SeverityLow,
		core.SeverityInfo,
	}

	severityColors := map[core.Severity]string{
		core.SeverityCritical: colorRed + colorBold,
		core.SeverityHigh:     colorRed,
		core.SeverityMedium:   colorYellow,
		core.SeverityLow:      colorBlue,
		core.SeverityInfo:     colorGreen,
	}

	severityLabels := map[core.Severity]string{
		core.SeverityCritical: "CRITICAL",
		core.SeverityHigh:     "HIGH    ",
		core.SeverityMedium:   "MEDIUM  ",
		core.SeverityLow:      "LOW     ",
		core.SeverityInfo:     "INFO    ",
	}

	issuesBySeverity := make(map[core.Severity][]*core.Issue)
	for _, issue := range report.Issues {
		issuesBySeverity[issue.Severity] = append(issuesBySeverity[issue.Severity], issue)
	}

	totalIssues := 0
	for _, sev := range severityOrder {
		issues := issuesBySeverity[sev]
		if len(issues) == 0 {
			continue
		}
		totalIssues += len(issues)

		color := severityColors[sev]
		label := severityLabels[sev]

		fmt.Println()
		fmt.Printf("%s[%s] %d issue(s)"+colorReset+"\n", color, label, len(issues))
		fmt.Println(strings.Repeat("─", 80))

		for i, issue := range issues {
			fmt.Printf("%s  %d. %s"+colorReset+"\n", color, i+1, issue.Title)
			fmt.Printf("     Endpoint: %s %s\n", issue.Method, issue.Endpoint)
			fmt.Printf("     Type: %s\n", issue.Type)

			if len(issue.Responses) > 0 {
				resp := issue.Responses[0]
				fmt.Printf("     Status: %d\n", resp.StatusCode)
				if len(issue.Inputs) > 0 {
					inputSample := issue.Inputs[0]
					if len(inputSample) > 80 {
						inputSample = inputSample[:77] + "..."
					}
					fmt.Printf("     Input: %s\n", inputSample)
				}
			}

			if i < len(issues)-1 {
				fmt.Println()
			}
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))

	if totalIssues == 0 {
		fmt.Println(colorGreen + colorBold + "✓ No issues found!" + colorReset)
	} else {
		fmt.Printf(colorBold+"Total Issues: "+colorReset+"%d", totalIssues)
		for _, sev := range severityOrder {
			if count, ok := report.Stats.BySeverity[sev]; ok && count > 0 {
				fmt.Printf(" | %s%s: %d"+colorReset, severityColors[sev], strings.TrimSpace(severityLabels[sev]), count)
			}
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println(colorCyan + "For detailed reports, see: " + r.config.OutputDir + colorReset)
	fmt.Println()
}

func (r *Reporter) writeJSON(report *Report) error {
	data := map[string]interface{}{
		"version": "1.0",
		"scan_info": map[string]interface{}{
			"start_time":   report.StartTime.Format(time.RFC3339),
			"end_time":     report.EndTime.Format(time.RFC3339),
			"duration":     report.Duration.Seconds(),
			"target_url":   report.TargetURL,
			"api_title":    report.APITitle,
			"seed":         report.Seed,
			"total_cases":  report.Stats.TotalTestCases,
			"completed":    report.Stats.Completed,
			"skipped":      report.Stats.Skipped,
			"failed":       report.Stats.Failed,
		},
		"coverage": map[string]interface{}{
			"endpoint_coverage": report.Coverage.EndpointCoverage(),
			"endpoints_tested":  report.Coverage.EndpointsTested,
			"methods_tested":    report.Coverage.MethodsTested,
			"response_codes":    report.Coverage.ResponseCodes,
		},
		"stats_by_severity": report.Stats.BySeverity,
		"stats_by_type":     report.Stats.ByType,
		"issues":            r.serializeIssues(report.Issues),
	}

	filePath := filepath.Join(r.config.OutputDir, "report.json")
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, jsonData, 0644)
}

func (r *Reporter) writeHTML(report *Report) error {
	htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Fuzzer Report - {{.APITitle}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; font-size: 28px; }
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
        .issues { margin-top: 30px; }
        .issue { background: #16213e; margin-bottom: 15px; border-radius: 10px; overflow: hidden; }
        .issue-header { padding: 15px 20px; cursor: pointer; display: flex; align-items: center; gap: 15px; }
        .issue-header:hover { background: #0f3460; }
        .severity-badge { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .badge-critical { background: #ff4757; color: white; }
        .badge-high { background: #ff6b81; color: white; }
        .badge-medium { background: #ffa502; color: black; }
        .badge-low { background: #70a1ff; color: white; }
        .badge-info { background: #7bed9f; color: black; }
        .issue-title { flex: 1; font-weight: 500; }
        .issue-endpoint { color: #888; font-size: 14px; }
        .issue-content { padding: 0 20px; max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }
        .issue-content.open { max-height: 2000px; padding-bottom: 20px; }
        .detail-section { margin-top: 15px; }
        .detail-section h4 { color: #00d4ff; margin-bottom: 10px; font-size: 14px; text-transform: uppercase; }
        pre { background: #0a0a1a; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
        code { font-family: 'Courier New', monospace; }
        .curl { background: #2d3436; padding: 10px; border-radius: 6px; font-size: 12px; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { color: #00d4ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ API Fuzzer Security Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="label">Target URL</div>
                    <div class="value" style="font-size: 16px;">{{.TargetURL}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">API Title</div>
                    <div class="value" style="font-size: 16px;">{{.APITitle}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Duration</div>
                    <div class="value">{{.Duration}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Seed</div>
                    <div class="value">{{.Seed}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Test Cases</div>
                    <div class="value">{{.Stats.Completed}} / {{.Stats.TotalTestCases}}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Endpoint Coverage</div>
                    <div class="value">{{printf "%.1f" .Coverage.EndpointCoverage}}%</div>
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

        <div class="issues">
            <h2>Issues ({{len .Issues}})</h2>
            {{range $i, $issue := .Issues}}
            <div class="issue">
                <div class="issue-header" onclick="toggleIssue({{$i}})">
                    <span class="severity-badge badge-{{$issue.Severity}}">{{$issue.Severity}}</span>
                    <span class="issue-title">{{$issue.Title}}</span>
                    <span class="issue-endpoint">{{$issue.Method}} {{$issue.Endpoint}}</span>
                    <span style="color: #888;">▼</span>
                </div>
                <div class="issue-content" id="issue-{{$i}}">
                    <div class="detail-section">
                        <h4>Description</h4>
                        <p>{{$issue.Description}}</p>
                    </div>
                    <div class="detail-section">
                        <h4>Type</h4>
                        <p>{{$issue.Type}}</p>
                    </div>
                    {{if len $issue.Inputs}}
                    <div class="detail-section">
                        <h4>Triggering Inputs</h4>
                        <ul>
                            {{range $input := $issue.Inputs}}
                            <li><code>{{$input}}</code></li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                    {{if len $issue.Responses}}
                    <div class="detail-section">
                        <h4>Response</h4>
                        {{$resp := index $issue.Responses 0}}
                        <table>
                            <tr><th>Status</th><td>{{$resp.StatusCode}} {{$resp.Status}}</td></tr>
                            <tr><th>Duration</th><td>{{$resp.Duration}}</td></tr>
                        </table>
                        {{if $resp.Body}}
                        <h4 style="margin-top: 15px;">Response Body</h4>
                        <pre><code>{{$resp.Body}}</code></pre>
                        {{end}}
                    </div>
                    {{end}}
                    {{if len $issue.Requests}}
                    <div class="detail-section">
                        <h4>Reproduce</h4>
                        <div class="curl">
                            <code>{{index $issue.Requests 0 | ToCurl}}</code>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
    </div>

    <script>
        function toggleIssue(id) {
            const content = document.getElementById('issue-' + id);
            content.classList.toggle('open');
        }
    </script>
</body>
</html>
`

	funcMap := template.FuncMap{
		"ToCurl": core.ToCurlCommand,
		"SeverityCount": func(bySeverity map[core.Severity]int, sev string) int {
			return bySeverity[core.Severity(sev)]
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	filePath := filepath.Join(r.config.OutputDir, "report.html")
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, report)
}

func (r *Reporter) writeSARIF(report *Report) error {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "API Fuzzer",
						"version":        "1.0.0",
						"informationUri": "https://github.com/api-fuzzer/apifuzzer",
						"rules":          r.buildSARIFRules(report.Issues),
					},
				},
				"invocations": []interface{}{
					map[string]interface{}{
						"executionSuccessful": true,
						"startTimeUtc":        report.StartTime.UTC().Format(time.RFC3339),
						"endTimeUtc":          report.EndTime.UTC().Format(time.RFC3339),
					},
				},
				"artifacts": []interface{}{
					map[string]interface{}{
						"location": map[string]interface{}{
							"uri": report.TargetURL,
						},
					},
				},
				"results": r.buildSARIFResults(report.Issues),
			},
		},
	}

	filePath := filepath.Join(r.config.OutputDir, "report.sarif")
	jsonData, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, jsonData, 0644)
}

func (r *Reporter) buildSARIFRules(issues []*core.Issue) []interface{} {
	seenRules := make(map[string]bool)
	var rules []interface{}

	for _, issue := range issues {
		ruleID := string(issue.Type)
		if seenRules[ruleID] {
			continue
		}
		seenRules[ruleID] = true

		rules = append(rules, map[string]interface{}{
			"id": ruleID,
			"shortDescription": map[string]interface{}{
				"text": issue.Title,
			},
			"fullDescription": map[string]interface{}{
				"text": issue.Description,
			},
			"defaultConfiguration": map[string]interface{}{
				"level": sarifLevel(issue.Severity),
			},
		})
	}

	return rules
}

func (r *Reporter) buildSARIFResults(issues []*core.Issue) []interface{} {
	var results []interface{}

	for i, issue := range issues {
		var codeFlows []interface{}

		if len(issue.Requests) > 0 && len(issue.Responses) > 0 {
			codeFlows = append(codeFlows, map[string]interface{}{
				"threadFlows": []interface{}{
					map[string]interface{}{
						"locations": []interface{}{
							map[string]interface{}{
								"location": map[string]interface{}{
									"physicalLocation": map[string]interface{}{
										"artifactLocation": map[string]interface{}{
											"uri": issue.Method + " " + issue.Endpoint,
										},
									},
									"message": map[string]interface{}{
										"text": "Request: " + issue.Requests[0].Method + " " + issue.Requests[0].URL,
									},
								},
							},
						},
					},
				},
			})
		}

		result := map[string]interface{}{
			"ruleId":    string(issue.Type),
			"ruleIndex": i,
			"level":     sarifLevel(issue.Severity),
			"message": map[string]interface{}{
				"text": issue.Title + ": " + issue.Description,
			},
			"locations": []interface{}{
				map[string]interface{}{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": issue.Method + " " + issue.Endpoint,
						},
					},
				},
			},
			"partialFingerprints": map[string]interface{}{
				"issueFingerprint": issue.Fingerprint,
			},
		}

		if len(codeFlows) > 0 {
			result["codeFlows"] = codeFlows
		}

		results = append(results, result)
	}

	return results
}

func sarifLevel(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func (r *Reporter) serializeIssues(issues []*core.Issue) []interface{} {
	var result []interface{}

	for _, issue := range issues {
		issueData := map[string]interface{}{
			"id":           issue.ID,
			"fingerprint":  issue.Fingerprint,
			"severity":     issue.Severity,
			"type":         issue.Type,
			"title":        issue.Title,
			"description":  issue.Description,
			"endpoint":     issue.Endpoint,
			"method":       issue.Method,
			"inputs":       issue.Inputs,
			"test_case_ids": issue.TestCaseIDs,
			"created_at":   issue.CreatedAt.Format(time.RFC3339),
		}

		if len(issue.Requests) > 0 {
			req := issue.Requests[0]
			issueData["request"] = map[string]interface{}{
				"method":  req.Method,
				"url":     req.URL,
				"headers": req.Headers,
				"body":    req.Body,
				"curl":    core.ToCurlCommand(req),
			}
		}

		if len(issue.Responses) > 0 {
			resp := issue.Responses[0]
			issueData["response"] = map[string]interface{}{
				"status_code": resp.StatusCode,
				"status":      resp.Status,
				"headers":     resp.Headers,
				"body":        resp.Body,
				"truncated":   resp.BodyTruncated,
				"duration_ms": resp.Duration.Milliseconds(),
			}
		}

		result = append(result, issueData)
	}

	sort.Slice(result, func(i, j int) bool {
		severityOrder := map[core.Severity]int{
			core.SeverityCritical: 5,
			core.SeverityHigh:     4,
			core.SeverityMedium:   3,
			core.SeverityLow:      2,
			core.SeverityInfo:     1,
		}
		issueI := issues[i]
		issueJ := issues[j]
		return severityOrder[issueI.Severity] > severityOrder[issueJ.Severity]
	})

	return result
}

func NewScanStats() *ScanStats {
	return &ScanStats{
		BySeverity: make(map[core.Severity]int),
		ByType:     make(map[core.IssueType]int),
	}
}

func (s *ScanStats) AddIssues(issues []*core.Issue) {
	for _, issue := range issues {
		s.BySeverity[issue.Severity]++
		s.ByType[issue.Type]++
	}
}
