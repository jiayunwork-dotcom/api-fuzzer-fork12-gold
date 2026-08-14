package audit

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"github.com/api-fuzzer/apifuzzer/internal/ratelimiter"
)

type DynamicProber struct {
	api       *core.API
	policy    *core.AuditPolicy
	config    *core.AuditConfig
	executor  *ratelimiter.RequestExecutor
	findings  []*core.AuditFinding
	baseURL   string
}

func NewDynamicProber(api *core.API, policy *core.AuditPolicy, config *core.AuditConfig) *DynamicProber {
	executor := ratelimiter.NewRequestExecutor(config.RateLimit, config.Auth, 10*1024)
	return &DynamicProber{
		api:      api,
		policy:   policy,
		config:   config,
		executor: executor,
		baseURL:  config.TargetURL,
		findings: make([]*core.AuditFinding, 0),
	}
}

func (dp *DynamicProber) Probe(ctx context.Context) []*core.AuditFinding {
	dp.checkAuthBypass(ctx)
	dp.checkCORS(ctx)
	dp.checkSecurityHeaders(ctx)
	dp.checkInfoLeak(ctx)
	dp.checkHTTPMethods(ctx)
	dp.checkContentType(ctx)
	return dp.filterBySeverity(dp.findings)
}

func (dp *DynamicProber) filterBySeverity(findings []*core.AuditFinding) []*core.AuditFinding {
	threshold := severityOrder(dp.config.SeverityThreshold)
	result := make([]*core.AuditFinding, 0)
	for _, f := range findings {
		if severityOrder(f.Severity) >= threshold {
			result = append(result, f)
		}
	}
	return result
}

func (dp *DynamicProber) addDynamicFinding(ruleID, endpoint, method string, evidence map[string]interface{}, req *core.HTTPRequest, resp *core.HTTPResponse) {
	if !IsRuleEnabled(ruleID, dp.policy, dp.config.Categories) {
		return
	}
	if endpoint != "" && IsPathExcluded(endpoint, dp.policy) {
		return
	}

	rule := GetRuleByID(ruleID)
	if rule == nil {
		return
	}

	severity := GetEffectiveSeverity(ruleID, dp.policy)
	finding := &core.AuditFinding{
		ID:            core.GenerateID(),
		RuleID:        ruleID,
		RuleCategory:  rule.Category,
		Severity:      severity,
		Title:         rule.Title,
		Description:   rule.Description,
		Endpoint:      endpoint,
		Method:        method,
		FixSuggestion: rule.FixSuggestion,
		Evidence:      evidence,
		IsStatic:      false,
		CreatedAt:     time.Now(),
	}
	if req != nil {
		finding.Requests = []*core.HTTPRequest{req}
	}
	if resp != nil {
		finding.Responses = []*core.HTTPResponse{resp}
	}
	finding.Fingerprint = computeFindingFingerprint(finding)
	dp.findings = append(dp.findings, finding)
}

func buildURL(baseURL, path string, pathParams, queryParams map[string]interface{}) string {
	url := baseURL
	if strings.HasSuffix(url, "/") {
		url = url[:len(url)-1]
	}
	fullPath := path
	for name, value := range pathParams {
		placeholder := "{" + name + "}"
		fullPath = strings.ReplaceAll(fullPath, placeholder, core.ToString(value))
	}
	if len(queryParams) > 0 {
		queryStr := core.MapToQueryString(queryParams)
		if queryStr != "" {
			fullPath += "?" + queryStr
		}
	}
	return url + fullPath
}

func (dp *DynamicProber) sendRequest(ctx context.Context, method, path string, headers map[string]string, body string, contentType string, authType string) (*core.HTTPRequest, *core.HTTPResponse, error) {
	pathParams := make(map[string]interface{})
	paramNames := getPathParamNames(path)
	for _, name := range paramNames {
		pathParams[name] = generateSampleValue(name)
	}

	fullURL := buildURL(dp.baseURL, path, pathParams, nil)

	req := &core.HTTPRequest{
		Method:      method,
		URL:           fullURL,
		Headers:     make(map[string]string),
		Cookies:     make(map[string]string),
		Body:          body,
		ContentType: contentType,
	}

	for k, v := range headers {
		req.Headers[k] = v
	}

	resp, err := dp.executor.Execute(ctx, req)
	return req, resp, err
}

func getPathParamNames(path string) []string {
	var params []string
	parts := strings.Split(path, "{")
	for i := 1; i < len(parts); i++ {
		if idx := strings.Index(parts[i], "}"); idx > 0 {
			params = append(params, parts[i][:idx])
		}
	}
	return params
}

func generateSampleValue(paramName string) string {
	lowerName := strings.ToLower(paramName)
	if strings.Contains(lowerName, "id") {
		return "1"
	}
	if strings.Contains(lowerName, "name") {
		return "test"
	}
	return "123"
}

func (dp *DynamicProber) checkAuthBypass(ctx context.Context) {
	globalSecurity := dp.api.Security

	for path, methods := range dp.api.Paths {
		for method, op := range methods {
			if !IsRuleEnabled("DYNAUTH-001", dp.policy, dp.config.Categories) {
				break
			}

			if IsPathExcluded(path, dp.policy) {
				continue
			}

			hasSecurity := len(globalSecurity) > 0 || len(op.Security) > 0
			if !hasSecurity {
				continue
			}

			noAuthHeaders := map[string]string{}
			req, resp, err := dp.sendRequestWithAuth(ctx, method, path, noAuthHeaders, "", "", "none")
			if err != nil {
				continue
			}

			if resp != nil && resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusMethodNotAllowed {
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					dp.addDynamicFinding("DYNAUTH-001", path, method, map[string]interface{}{
						"expected_status": []int{http.StatusUnauthorized, http.StatusForbidden},
						"actual_status": resp.StatusCode,
					}, req, resp)
				}
			}
		}
	}
}

func (dp *DynamicProber) sendRequestWithAuth(ctx context.Context, method, path string, headers map[string]string, body string, contentType string, authType string) (*core.HTTPRequest, *core.HTTPResponse, error) {
	originalAuth := dp.config.Auth
	if authType == "none" {
		dp.config.Auth = core.AuthConfig{}
		dp.executor = ratelimiter.NewRequestExecutor(dp.config.RateLimit, dp.config.Auth, 10*1024)
	}

	req, resp, err := dp.sendRequest(ctx, method, path, headers, body, contentType, authType)

	if authType == "none" {
		dp.config.Auth = originalAuth
		dp.executor = ratelimiter.NewRequestExecutor(dp.config.RateLimit, dp.config.Auth, 10*1024)
	}

	return req, resp, err
}

func (dp *DynamicProber) checkCORS(ctx context.Context) {
	for path, methods := range dp.api.Paths {
		for method := range methods {
			if !IsRuleEnabled("DYNCORS-001", dp.policy, dp.config.Categories) &&
				!IsRuleEnabled("DYNCORS-002", dp.policy, dp.config.Categories) &&
				!IsRuleEnabled("DYNCORS-003", dp.policy, dp.config.Categories) {
				break
			}

			if IsPathExcluded(path, dp.policy) {
				continue
			}

			headers := map[string]string{
				"Origin":                         "https://evil.example.com",
				"Access-Control-Request-Method":      method,
				"Access-Control-Request-Headers":     "Authorization, Content-Type",
			}

			req, resp, err := dp.sendRequest(ctx, "OPTIONS", path, headers, "", "", "")
			if err != nil {
				continue
			}

			if resp == nil {
				continue
			}

			allowOrigin := resp.Headers["Access-Control-Allow-Origin"]
			allowCredentials := resp.Headers["Access-Control-Allow-Credentials"]
			allowMethods := resp.Headers["Access-Control-Allow-Methods"]

			if allowOrigin == "*" {
				dp.addDynamicFinding("DYNCORS-001", path, method, map[string]interface{}{
					"allow_origin": allowOrigin,
				}, req, resp)
			}

			if allowOrigin == "*" && strings.ToLower(allowCredentials) == "true" {
				dp.addDynamicFinding("DYNCORS-002", path, method, map[string]interface{}{
					"allow_origin":      allowOrigin,
					"allow_credentials": allowCredentials,
				}, req, resp)
			}

			if allowMethods == "*" || strings.Contains(allowMethods, "*") {
				dp.addDynamicFinding("DYNCORS-003", path, method, map[string]interface{}{
					"allow_methods": allowMethods,
				}, req, resp)
			}
		}
	}
}

func (dp *DynamicProber) checkSecurityHeaders(ctx context.Context) {
	requiredHeaders := map[string]string{
		"DYNHEADER-001": "X-Content-Type-Options",
		"DYNHEADER-002": "Strict-Transport-Security",
		"DYNHEADER-003": "X-Frame-Options",
		"DYNHEADER-004": "Content-Security-Policy",
	}

	checkedPaths := make(map[string]bool)

	for path, methods := range dp.api.Paths {
		if checkedPaths[path] {
			continue
		}
		checkedPaths[path] = true

		for method := range methods {
			if IsPathExcluded(path, dp.policy) {
				continue
			}

			headersCheckNeeded := false
			for ruleID := range requiredHeaders {
				if IsRuleEnabled(ruleID, dp.policy, dp.config.Categories) {
					headersCheckNeeded = true
					break
				}
			}
			if !headersCheckNeeded {
				continue
			}

			if method != "GET" && method != "get" {
				continue
			}

			req, resp, err := dp.sendRequest(ctx, method, path, map[string]string{}, "", "", "")
			if err != nil || resp == nil {
				continue
			}

			for ruleID, headerName := range requiredHeaders {
				if !IsRuleEnabled(ruleID, dp.policy, dp.config.Categories) {
					continue
				}

				headerValue := resp.Headers[headerName]
				if headerValue == "" {
					headerValue = resp.Headers[strings.ToLower(headerName)]
				}
				if headerValue == "" {
					dp.addDynamicFinding(ruleID, path, method, map[string]interface{}{
						"missing_header": headerName,
					}, req, resp)
				}
			}
			break
		}
	}
}

func (dp *DynamicProber) checkInfoLeak(ctx context.Context) {
	leakPatterns := []struct {
		ruleID  string
		pattern string
	}{
		{"DYNLEAK-001", `(?i)(stack trace|stacktrace|traceback|exception|fatal error)`},
		{"DYNLEAK-002", `(?i)\/[a-z_]+\/[a-z_]+\/|\/var\/|\/etc\/|C:\\|D:\\`},
		{"DYNLEAK-003", `(?i)(mysql|postgres|ora-\d+|sql syntax|syntax error|constraint violation|duplicate entry)`},
		{"DYNLEAK-004", `(?i)(server: .+\/\d+\.\d+|x-powered-by:|x-aspnet-version:|x-drupal-cache:)`},
	}

	for path, methods := range dp.api.Paths {
		for method := range methods {
			if IsPathExcluded(path, dp.policy) {
				continue
			}

			anyLeakCheckNeeded := false
			for _, lp := range leakPatterns {
				if IsRuleEnabled(lp.ruleID, dp.policy, dp.config.Categories) {
					anyLeakCheckNeeded = true
					break
				}
			}
			if !anyLeakCheckNeeded {
				continue
			}

			invalidPath := path
			if strings.Contains(path, "{") {
				paramNames := getPathParamNames(path)
				for _, name := range paramNames {
					invalidPath = strings.ReplaceAll(invalidPath, "{"+name+"}", "INVALID_VALUE_'+name+'_!!@@")
				}
			}

			req, resp, err := dp.sendRequest(ctx, method, invalidPath, map[string]string{}, "", "", "")
			if err != nil || resp == nil {
				continue
			}

			if resp.StatusCode >= 400 || resp.StatusCode >= 500 {
				responseText := resp.Body
				for k, v := range resp.Headers {
					responseText += "\n" + k + ": " + v
				}

				for _, lp := range leakPatterns {
					if !IsRuleEnabled(lp.ruleID, dp.policy, dp.config.Categories) {
						continue
					}

					matched, _ := regexp.MatchString(lp.pattern, responseText)
					if matched {
						dp.addDynamicFinding(lp.ruleID, path, method, map[string]interface{}{
							"matched_pattern": lp.pattern,
						}, req, resp)
					}
				}
			}
		}
	}
}

func (dp *DynamicProber) checkHTTPMethods(ctx context.Context) {
	allMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}

	for path, methods := range dp.api.Paths {
		if !IsRuleEnabled("DYNMETHOD-001", dp.policy, dp.config.Categories) {
			break
		}

		if IsPathExcluded(path, dp.policy) {
			continue
		}

		definedMethods := make(map[string]bool)
		for method := range methods {
			definedMethods[strings.ToUpper(method)] = true
		}

		for _, testMethod := range allMethods {
			if definedMethods[testMethod] {
				continue
			}
			if testMethod == "OPTIONS" {
				continue
			}

			req, resp, err := dp.sendRequest(ctx, testMethod, path, map[string]string{}, "", "", "")
			if err != nil || resp == nil {
				continue
			}

			if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound &&
				resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					dp.addDynamicFinding("DYNMETHOD-001", path, testMethod, map[string]interface{}{
						"tested_method":     testMethod,
						"actual_status": resp.StatusCode,
						"expected_status": http.StatusMethodNotAllowed,
					}, req, resp)
				}
			}
		}
	}
}

func (dp *DynamicProber) checkContentType(ctx context.Context) {
	for path, methods := range dp.api.Paths {
		for method, op := range methods {
			if !IsRuleEnabled("DYNCONTENT-001", dp.policy, dp.config.Categories) {
				break
			}

			if IsPathExcluded(path, dp.policy) {
				continue
			}

			if op.RequestBody == nil {
				continue
			}

			expectedContentType := "application/json"
			for ct := range op.RequestBody.Content {
				expectedContentType = ct
				break
			}

			if strings.Contains(expectedContentType, "json") {
				wrongContentType := "application/xml"
				wrongBody := `<root><key>value</key></root>`

				req, resp, err := dp.sendRequest(ctx, method, path, map[string]string{}, wrongBody, wrongContentType, "")
				if err != nil || resp == nil {
					continue
				}

				if resp.StatusCode == http.StatusInternalServerError {
					dp.addDynamicFinding("DYNCONTENT-001", path, method, map[string]interface{}{
						"sent_content_type": wrongContentType,
						"expected_content_type": expectedContentType,
						"actual_status": resp.StatusCode,
					}, req, resp)
				}
			}
		}
	}
}
