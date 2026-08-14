package analyzer

import (
	"regexp"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type Analyzer struct {
	config              core.AnalyzerConfig
	infoLeakRegexes     []*regexp.Regexp
	customPatternRegexes []*compiledPattern
	responseHistory     map[string][]int
}

type compiledPattern struct {
	pattern    *regexp.Regexp
	definition core.CustomPattern
}

func NewAnalyzer(config core.AnalyzerConfig) (*Analyzer, error) {
	a := &Analyzer{
		config:          config,
		responseHistory: make(map[string][]int),
	}

	for _, p := range config.InfoLeakPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		a.infoLeakRegexes = append(a.infoLeakRegexes, re)
	}

	for _, p := range config.CustomPatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, err
		}
		a.customPatternRegexes = append(a.customPatternRegexes, &compiledPattern{
			pattern:    re,
			definition: p,
		})
	}

	return a, nil
}

func (a *Analyzer) Analyze(testCase *core.TestCase, req *core.HTTPRequest, resp *core.HTTPResponse) []*core.Issue {
	var issues []*core.Issue

	endpointKey := testCase.Operation.Method + " " + testCase.Operation.Path

	if resp.Error != nil && (resp.StatusCode == 0 || resp.StatusCode >= 500) {
		issues = append(issues, a.createIssue(
			core.SeverityCritical,
			core.IssueType5xxError,
			"Server Error or Connection Failure",
			resp.Error.Error(),
			endpointKey,
			testCase, req, resp,
		))
	} else if resp.StatusCode >= 500 {
		issues = append(issues, a.createIssue(
			core.SeverityCritical,
			core.IssueType5xxError,
			"Server Internal Error",
			"Server returned 5xx status code indicating an unhandled exception",
			endpointKey,
			testCase, req, resp,
		))
	}

	if resp.Duration > a.config.TimeoutThreshold {
		issues = append(issues, a.createIssue(
			core.SeverityHigh,
			core.IssueTypeTimeout,
			"Slow Response",
			"Response time exceeded threshold",
			endpointKey,
			testCase, req, resp,
		))
	}

	if strings.Contains(strings.ToLower(resp.Body), "stack") ||
		strings.Contains(strings.ToLower(resp.Body), "traceback") ||
		strings.Contains(resp.Body, "at ") && strings.Contains(resp.Body, ".java:") ||
		strings.Contains(resp.Body, "File \"") && strings.Contains(resp.Body, "\", line") {
		issues = append(issues, a.createIssue(
			core.SeverityHigh,
			core.IssueTypeStackTrace,
			"Stack Trace Disclosure",
			"Response contains stack trace information",
			endpointKey,
			testCase, req, resp,
		))
	}

	if strings.Contains(strings.ToLower(resp.Body), "sql") &&
		(strings.Contains(strings.ToLower(resp.Body), "syntax") ||
			strings.Contains(strings.ToLower(resp.Body), "error") ||
			strings.Contains(strings.ToLower(resp.Body), "ORA-") ||
			strings.Contains(strings.ToLower(resp.Body), "MySQL")) {
		issues = append(issues, a.createIssue(
			core.SeverityHigh,
			core.IssueTypeDbError,
			"Database Error Disclosure",
			"Response contains database error information",
			endpointKey,
			testCase, req, resp,
		))
	}

	for _, re := range a.infoLeakRegexes {
		if re.MatchString(resp.Body) {
			matches := re.FindAllString(resp.Body, -1)
			if len(matches) > 0 {
				matchSample := strings.Join(matches[:3], ", ")
				issues = append(issues, a.createIssue(
					core.SeverityMedium,
					core.IssueTypeInfoLeak,
					"Potential Information Leak",
					"Response matched pattern: "+matchSample,
					endpointKey,
					testCase, req, resp,
				))
			}
		}
	}

	infoLeakHeaders := []string{
		"X-Powered-By",
		"Server",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Generator",
		"X-Drupal-Cache",
	}
	for _, header := range infoLeakHeaders {
		if val, ok := resp.Headers[header]; ok && val != "" {
			issues = append(issues, a.createIssue(
				core.SeverityLow,
				core.IssueTypeInfoLeak,
				"Information Leak in Response Header",
				header+": "+val,
				endpointKey,
				testCase, req, resp,
			))
		}
	}

	if a.checkInconsistentResponse(endpointKey, resp.StatusCode) {
		issues = append(issues, a.createIssue(
			core.SeverityMedium,
			core.IssueTypeInconsistent,
			"Inconsistent Response",
			"Same request returned different status codes",
			endpointKey,
			testCase, req, resp,
		))
	}

	if a.isMaliciousPayload(testCase) && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		issues = append(issues, a.createIssue(
			core.SeverityHigh,
			core.IssueTypeUnexpectedSuccess,
			"Unexpected Success with Malicious Payload",
			"Malicious input was accepted by the server",
			endpointKey,
			testCase, req, resp,
		))
	}

	for _, cp := range a.customPatternRegexes {
		if cp.pattern.MatchString(resp.Body) {
			matches := cp.pattern.FindAllString(resp.Body, -1)
			if len(matches) > 0 {
				matchSample := strings.Join(matches[:3], ", ")
				issues = append(issues, a.createIssue(
					cp.definition.Severity,
					core.IssueTypeCustom,
					"Custom Rule Match: "+cp.definition.Name,
					cp.definition.Description+": "+matchSample,
					endpointKey,
					testCase, req, resp,
				))
			}
		}
	}

	for _, issue := range issues {
		issue.ComputeFingerprint()
	}

	return issues
}

func (a *Analyzer) createIssue(
	severity core.Severity,
	issueType core.IssueType,
	title, description, endpoint string,
	testCase *core.TestCase,
	req *core.HTTPRequest,
	resp *core.HTTPResponse,
) *core.Issue {
	issue := &core.Issue{
		ID:          core.GenerateID(),
		Severity:    severity,
		Type:        issueType,
		Title:       title,
		Description: description,
		Endpoint:    testCase.Operation.Path,
		Method:      testCase.Operation.Method,
		Requests:    []*core.HTTPRequest{req},
		Responses:   []*core.HTTPResponse{resp},
		TestCaseIDs: []string{testCase.ID},
		Inputs:      []string{a.extractInput(testCase)},
		CreatedAt:   time.Now(),
	}
	issue.ComputeFingerprint()
	return issue
}

func (a *Analyzer) checkInconsistentResponse(endpointKey string, statusCode int) bool {
	history, ok := a.responseHistory[endpointKey]
	if !ok {
		a.responseHistory[endpointKey] = []int{statusCode}
		return false
	}

	for _, code := range history {
		if code != statusCode && code >= 200 && code < 500 && statusCode >= 200 && statusCode < 500 {
			a.responseHistory[endpointKey] = append(history, statusCode)
			return true
		}
	}

	a.responseHistory[endpointKey] = append(history, statusCode)
	return false
}

func (a *Analyzer) isMaliciousPayload(testCase *core.TestCase) bool {
	maliciousPatterns := []string{
		"<script",
		"alert(",
		"onerror=",
		"OR 1=1",
		"UNION SELECT",
		"DROP TABLE",
		"../../",
		"%s%s%s",
		"phpinfo()",
	}

	allParams := make(map[string]interface{})
	for k, v := range testCase.PathParams {
		allParams[k] = v
	}
	for k, v := range testCase.QueryParams {
		allParams[k] = v
	}
	for k, v := range testCase.HeaderParams {
		allParams[k] = v
	}
	for k, v := range testCase.CookieParams {
		allParams[k] = v
	}

	for _, v := range allParams {
		strVal := core.ToString(v)
		for _, pattern := range maliciousPatterns {
			if strings.Contains(strings.ToLower(strVal), strings.ToLower(pattern)) {
				return true
			}
		}
	}

	if testCase.Body != nil {
		bodyStr := core.ToString(testCase.Body)
		for _, pattern := range maliciousPatterns {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}

func (a *Analyzer) extractInput(testCase *core.TestCase) string {
	var parts []string
	for k, v := range testCase.PathParams {
		parts = append(parts, k+"="+core.ToString(v))
	}
	for k, v := range testCase.QueryParams {
		parts = append(parts, k+"="+core.ToString(v))
	}
	return strings.Join(parts, ", ")
}

func CheckSeverityThreshold(severity core.Severity, threshold core.Severity) bool {
	severityOrder := map[core.Severity]int{
		core.SeverityCritical: 5,
		core.SeverityHigh:     4,
		core.SeverityMedium:   3,
		core.SeverityLow:      2,
		core.SeverityInfo:     1,
	}

	return severityOrder[severity] > severityOrder[threshold]
}
