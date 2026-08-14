package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type StaticAnalyzer struct {
	api      *core.API
	policy   *core.AuditPolicy
	config   *core.AuditConfig
	findings []*core.AuditFinding
}

func NewStaticAnalyzer(api *core.API, policy *core.AuditPolicy, config *core.AuditConfig) *StaticAnalyzer {
	return &StaticAnalyzer{
		api:      api,
		policy:   policy,
		config:   config,
		findings: make([]*core.AuditFinding, 0),
	}
}

func (sa *StaticAnalyzer) Analyze() []*core.AuditFinding {
	sa.checkAuthCoverage()
	sa.checkDataExposure()
	sa.checkInputValidation()
	sa.checkRateLimit()
	sa.checkVersioning()
	sa.checkErrorHandling()
	sa.checkCustomRules()
	return sa.filterBySeverity(sa.findings)
}

func (sa *StaticAnalyzer) GetAllFindings() []*core.AuditFinding {
	return sa.findings
}

func (sa *StaticAnalyzer) filterBySeverity(findings []*core.AuditFinding) []*core.AuditFinding {
	threshold := severityOrder(sa.config.SeverityThreshold)
	result := make([]*core.AuditFinding, 0)
	for _, f := range findings {
		if severityOrder(f.Severity) >= threshold {
			result = append(result, f)
		}
	}
	return result
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

func (sa *StaticAnalyzer) addFinding(ruleID, endpoint, method string, evidence map[string]interface{}, isStatic bool) {
	if !IsRuleEnabled(ruleID, sa.policy, sa.config.Categories) {
		return
	}
	if endpoint != "" && IsPathExcluded(endpoint, sa.policy) {
		return
	}

	rule := GetRuleByID(ruleID)
	if rule == nil {
		for _, cr := range sa.policy.CustomRules {
			if cr.ID == ruleID {
				rule = &core.AuditRule{
					ID:            cr.ID,
					Category:      cr.Category,
					Severity:      cr.Severity,
					Title:         cr.Title,
					Description:   cr.Description,
					FixSuggestion: cr.FixSuggestion,
					Enabled:       true,
				}
				break
			}
		}
	}
	if rule == nil {
		return
	}

	severity := GetEffectiveSeverity(ruleID, sa.policy)
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
		IsStatic:      isStatic,
		CreatedAt:     time.Now(),
	}
	finding.Fingerprint = computeFindingFingerprint(finding)
	sa.findings = append(sa.findings, finding)
}

func computeFindingFingerprint(f *core.AuditFinding) string {
	fp := fmt.Sprintf("%s|%s|%s|%s", f.RuleID, f.Method, f.Endpoint, f.Description)
	hash := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(hash[:])[:16]
}

func (sa *StaticAnalyzer) checkAuthCoverage() {
	globalSecurity := sa.api.Security
	writeMethods := map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	sensitiveMethods := map[string]bool{"DELETE": true, "PUT": true, "PATCH": true}

	hasGlobalSecurity := len(globalSecurity) > 0
	unprotectedWriteOps := 0
	totalWriteOps := 0

	for path, methods := range sa.api.Paths {
		for method, op := range methods {
			if !IsRuleEnabled("AUTH-001", sa.policy, sa.config.Categories) &&
				!IsRuleEnabled("AUTH-002", sa.policy, sa.config.Categories) &&
				!IsRuleEnabled("AUTH-003", sa.policy, sa.config.Categories) {
				break
			}

			hasOpSecurity := len(op.Security) > 0
			isProtected := hasGlobalSecurity || hasOpSecurity

			if !isProtected {
				sa.addFinding("AUTH-001", path, method, map[string]interface{}{
					"has_global_security": hasGlobalSecurity,
					"has_op_security":     hasOpSecurity,
				}, true)
			}

			if writeMethods[strings.ToUpper(method)] {
				totalWriteOps++
				if !isProtected {
					unprotectedWriteOps++
					sa.addFinding("AUTH-002", path, method, map[string]interface{}{
						"method": method,
					}, true)
				}
			}

			if sensitiveMethods[strings.ToUpper(method)] && !isProtected {
				sa.addFinding("AUTH-003", path, method, map[string]interface{}{
					"method": method,
				}, true)
			}
		}
	}

	if hasGlobalSecurity && unprotectedWriteOps > 0 {
		sa.addFinding("AUTH-004", "", "", map[string]interface{}{
			"unprotected_write_ops": unprotectedWriteOps,
			"total_write_ops":       totalWriteOps,
		}, true)
	}
}

func (sa *StaticAnalyzer) checkDataExposure() {
	sensitivePatterns := GetSensitiveFieldPatterns(sa.policy)

	for path, methods := range sa.api.Paths {
		for method, op := range methods {
			if IsPathExcluded(path, sa.policy) {
				continue
			}

			for _, resp := range op.Responses {
				for _, mt := range resp.Content {
					if mt.Schema != nil {
						sa.checkSchemaForSensitiveFields(path, method, mt.Schema, sensitivePatterns, "")
						sa.checkFullUserObject(path, method, mt.Schema)
					}
				}
			}

			if strings.ToUpper(method) == "GET" {
				hasPagination := false
				paginationParams := []string{"limit", "offset", "page", "page_size", "per_page", "size", "count"}
				for _, param := range op.Parameters {
					lowerName := strings.ToLower(param.Name)
					for _, pp := range paginationParams {
						if strings.Contains(lowerName, pp) {
							hasPagination = true
							break
						}
					}
					if hasPagination {
						break
					}
				}
				if !hasPagination && (strings.Contains(strings.ToLower(path), "list") ||
					strings.HasSuffix(strings.ToLower(path), "s") ||
					strings.Contains(strings.ToLower(path), "search")) {
					sa.addFinding("DATA-003", path, method, map[string]interface{}{
						"path": path,
					}, true)
				}
			}
		}
	}
}

func (sa *StaticAnalyzer) checkSchemaForSensitiveFields(path, method string, schema *core.Schema, patterns []string, prefix string) {
	if schema == nil {
		return
	}

	if schema.Properties != nil {
		for propName, propSchema := range schema.Properties {
			fullName := propName
			if prefix != "" {
				fullName = prefix + "." + propName
			}

			lowerName := strings.ToLower(propName)
			for _, pattern := range patterns {
				matched, _ := regexp.MatchString("(?i)"+pattern, lowerName)
				if matched {
					sa.addFinding("DATA-001", path, method, map[string]interface{}{
						"field":         fullName,
						"matched_rule":  pattern,
						"schema_type":   propSchema.Type,
					}, true)
				}
			}

			if propSchema.Type == "object" || propSchema.Properties != nil {
				sa.checkSchemaForSensitiveFields(path, method, propSchema, patterns, fullName)
			}
			if propSchema.Type == "array" && propSchema.Items != nil {
				sa.checkSchemaForSensitiveFields(path, method, propSchema.Items, patterns, fullName+"[]")
			}
		}
	}
}

func (sa *StaticAnalyzer) checkFullUserObject(path, method string, schema *core.Schema) {
	if schema == nil || schema.Properties == nil {
		return
	}

	propNames := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		propNames = append(propNames, strings.ToLower(name))
	}

	userIndicators := []string{"user", "account", "profile"}
	sensitiveUserFields := []string{"password", "token", "secret", "ssn", "credit_card", "cvv", "pin"}

	isUserObject := false
	for _, indicator := range userIndicators {
		for _, name := range propNames {
			if strings.Contains(name, indicator) {
				isUserObject = true
				break
			}
		}
		if isUserObject {
			break
		}
	}

	if !isUserObject {
		return
	}

	fieldCount := len(schema.Properties)
	hasSensitiveField := false
	for _, sensitive := range sensitiveUserFields {
		for _, name := range propNames {
			if strings.Contains(name, sensitive) {
				hasSensitiveField = true
				break
			}
		}
		if hasSensitiveField {
			break
		}
	}

	if fieldCount > 5 && !hasSensitiveField {
		sa.addFinding("DATA-002", path, method, map[string]interface{}{
			"field_count": fieldCount,
			"fields":      propNames,
		}, true)
	}
}

func (sa *StaticAnalyzer) checkInputValidation() {
	for path, methods := range sa.api.Paths {
		for method, op := range methods {
			if IsPathExcluded(path, sa.policy) {
				continue
			}

			for _, param := range op.Parameters {
				if param.Schema == nil || param.Schema.Type == "" {
					sa.addFinding("INPUT-001", path, method, map[string]interface{}{
						"param_name":     param.Name,
						"param_location": param.Location,
					}, true)
					continue
				}

				if param.Schema.Type == "string" && param.Schema.MaxLength == nil {
					sa.addFinding("INPUT-002", path, method, map[string]interface{}{
						"param_name":     param.Name,
						"param_location": param.Location,
					}, true)
				}

				if (param.Schema.Type == "integer" || param.Schema.Type == "number") &&
					(param.Schema.Minimum == nil || param.Schema.Maximum == nil) {
					sa.addFinding("INPUT-003", path, method, map[string]interface{}{
						"param_name":     param.Name,
						"param_location": param.Location,
						"param_type":     param.Schema.Type,
						"has_minimum":    param.Schema.Minimum != nil,
						"has_maximum":    param.Schema.Maximum != nil,
					}, true)
				}
			}

			if op.RequestBody != nil && op.RequestBody.Required {
				hasSchema := false
				for _, mt := range op.RequestBody.Content {
					if mt.Schema != nil {
						hasSchema = true
						break
					}
				}
				if !hasSchema {
					sa.addFinding("INPUT-004", path, method, map[string]interface{}{
						"content_types": getContentTypes(op.RequestBody.Content),
					}, true)
				}
			}
		}
	}
}

func getContentTypes(content map[string]*core.MediaType) []string {
	types := make([]string, 0, len(content))
	for ct := range content {
		types = append(types, ct)
	}
	return types
}

func (sa *StaticAnalyzer) checkRateLimit() {
	hasRateLimitExtension := false

	if sa.api.Components != nil {
		if sa.api.Components.SecuritySchemes != nil {
			for name := range sa.api.Components.SecuritySchemes {
				if strings.Contains(strings.ToLower(name), "rate") ||
					strings.Contains(strings.ToLower(name), "limit") {
					hasRateLimitExtension = true
					break
				}
			}
		}
	}

	if !hasRateLimitExtension {
		sa.addFinding("RATE-001", "", "", map[string]interface{}{
			"spec_title": sa.api.Title,
		}, true)
	}

	highFreqPatterns := []string{
		"login", "signin", "auth", "register", "signup",
		"password", "reset", "forgot", "recover",
		"otp", "verify", "confirm",
	}

	for path, methods := range sa.api.Paths {
		for method := range methods {
			if IsPathExcluded(path, sa.policy) {
				continue
			}

			lowerPath := strings.ToLower(path)
			isHighFreq := false
			for _, pattern := range highFreqPatterns {
				if strings.Contains(lowerPath, pattern) {
					isHighFreq = true
					break
				}
			}

			if isHighFreq {
				sa.addFinding("RATE-002", path, method, map[string]interface{}{
					"path":     path,
					"category": "high-frequency-endpoint",
				}, true)
			}
		}
	}
}

func (sa *StaticAnalyzer) checkVersioning() {
	versionPattern := regexp.MustCompile(`^/v\d+`)

	for path := range sa.api.Paths {
		if IsPathExcluded(path, sa.policy) {
			continue
		}

		if !versionPattern.MatchString(path) && !strings.Contains(path, "/version") {
			sa.addFinding("VERSION-001", path, "", map[string]interface{}{
				"path": path,
			}, true)
		}
	}

	for path, methods := range sa.api.Paths {
		for method, op := range methods {
			if IsPathExcluded(path, sa.policy) {
				continue
			}

			if op.Deprecated {
				hasSunset := false
				for headerName := range op.Responses {
					if strings.Contains(strings.ToLower(headerName), "sunset") {
						hasSunset = true
						break
					}
				}
				if !hasSunset {
					sa.addFinding("VERSION-002", path, method, map[string]interface{}{
						"deprecated": true,
					}, true)
				}
			}
		}
	}
}

func (sa *StaticAnalyzer) checkErrorHandling() {
	for path, methods := range sa.api.Paths {
		for method, op := range methods {
			if IsPathExcluded(path, sa.policy) {
				continue
			}

			has4xx := false
			has5xx := false
			errorResponses := make([]string, 0)

			for code := range op.Responses {
				errorResponses = append(errorResponses, code)
				if len(code) == 3 && code[0] == '4' {
					has4xx = true
				}
				if len(code) == 3 && code[0] == '5' {
					has5xx = true
				}
			}

			if !has4xx {
				sa.addFinding("ERROR-001", path, method, map[string]interface{}{
					"defined_responses": errorResponses,
				}, true)
			}

			if !has5xx {
				sa.addFinding("ERROR-002", path, method, map[string]interface{}{
					"defined_responses": errorResponses,
				}, true)
			}

			for code, resp := range op.Responses {
				if len(code) == 3 && (code[0] == '4' || code[0] == '5') {
					for _, mt := range resp.Content {
						if mt.Schema != nil {
							hasErrorCode := false
							hasMessage := false

							if mt.Schema.Properties != nil {
								for propName := range mt.Schema.Properties {
									lowerName := strings.ToLower(propName)
									if strings.Contains(lowerName, "error") && strings.Contains(lowerName, "code") {
										hasErrorCode = true
									}
									if strings.Contains(lowerName, "message") || strings.Contains(lowerName, "msg") {
										hasMessage = true
									}
									if lowerName == "code" {
										hasErrorCode = true
									}
								}
							}

							if !hasErrorCode {
								sa.addFinding("ERROR-003", path, method, map[string]interface{}{
									"error_code": code,
								}, true)
							}
							if !hasMessage {
								sa.addFinding("ERROR-004", path, method, map[string]interface{}{
									"error_code": code,
								}, true)
							}
						}
					}
				}
			}
		}
	}
}

func (sa *StaticAnalyzer) checkCustomRules() {
	for _, rule := range sa.policy.CustomRules {
		if !IsRuleEnabled(rule.ID, sa.policy, sa.config.Categories) {
			continue
		}

		matched := false
		for path, methods := range sa.api.Paths {
			for method, op := range methods {
				if IsPathExcluded(path, sa.policy) {
					continue
				}

				if rule.JSONPath != "" {
					result := evaluateJSONPath(op, rule.JSONPath)
					if result != nil {
						conditionMet := evaluateCondition(result, rule.Condition)
						if conditionMet {
							sa.addFinding(rule.ID, path, method, map[string]interface{}{
								"jsonpath_result": result,
								"condition":       rule.Condition,
							}, true)
							matched = true
						}
					}
				}
			}
		}

		if !matched && strings.HasPrefix(rule.ID, "CUSTOM-") {
		}
	}
}

func evaluateJSONPath(op *core.Operation, jsonPath string) interface{} {
	pathParts := strings.Split(strings.Trim(jsonPath, "$."), ".")
	var current interface{} = op

	for _, part := range pathParts {
		switch curr := current.(type) {
		case *core.Operation:
			current = getFieldFromOperation(curr, part)
		case map[string]interface{}:
			current = curr[part]
		default:
			return nil
		}
		if current == nil {
			return nil
		}
	}

	return current
}

func getFieldFromOperation(op *core.Operation, field string) interface{} {
	switch strings.ToLower(field) {
	case "method":
		return op.Method
	case "path":
		return op.Path
	case "summary":
		return op.Summary
	case "description":
		return op.Description
	case "operationid":
		return op.OperationID
	case "tags":
		return op.Tags
	case "parameters":
		return op.Parameters
	case "deprecated":
		return op.Deprecated
	case "security":
		return op.Security
	default:
		return nil
	}
}

func evaluateCondition(value interface{}, condition map[string]interface{}) bool {
	if len(condition) == 0 {
		return value != nil
	}

	condType, _ := condition["type"].(string)
	field, _ := condition["field"].(string)
	expected := condition["value"]

	switch condType {
	case "", "exists":
		return value != nil

	case "field_exists":
		if valueMap, ok := value.(map[string]interface{}); ok {
			_, exists := valueMap[field]
			if expectedBool, ok := expected.(bool); ok {
				return exists == expectedBool
			}
			return exists
		}
		return false

	case "field_not_exists":
		if valueMap, ok := value.(map[string]interface{}); ok {
			_, exists := valueMap[field]
			if expectedBool, ok := expected.(bool); ok {
				return !exists == expectedBool
			}
			return !exists
		}
		return true

	case "has_extension":
		if valueMap, ok := value.(map[string]interface{}); ok {
			extKey := "x-" + field
			_, exists := valueMap[extKey]
			if expectedBool, ok := expected.(bool); ok {
				return exists == expectedBool
			}
			return exists
		}
		return false

	case "==", "eq":
		return compareValues(value, expected) == 0

	case "!=", "ne":
		return compareValues(value, expected) != 0

	case ">", "gt":
		return compareValues(value, expected) > 0

	case "<", "lt":
		return compareValues(value, expected) < 0

	case ">=", "gte":
		return compareValues(value, expected) >= 0

	case "<=", "lte":
		return compareValues(value, expected) <= 0

	case "contains":
		if strVal, ok := value.(string); ok {
			if strExpected, ok := expected.(string); ok {
				return strings.Contains(strVal, strExpected)
			}
		}
		return false

	case "matches":
		if strVal, ok := value.(string); ok {
			if strExpected, ok := expected.(string); ok {
				matched, _ := regexp.MatchString(strExpected, strVal)
				return matched
			}
		}
		return false
	}

	return false
}

func compareValues(a, b interface{}) int {
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return strings.Compare(av, bv)
		}
	case bool:
		if bv, ok := b.(bool); ok {
			if av == bv {
				return 0
			}
			if av {
				return 1
			}
			return -1
		}
	case int:
		if bv, ok := b.(int); ok {
			if av == bv {
				return 0
			}
			if av > bv {
				return 1
			}
			return -1
		}
		if bv, ok := b.(float64); ok {
			return compareValues(float64(av), bv)
		}
	case float64:
		if bv, ok := b.(float64); ok {
			if av == bv {
				return 0
			}
			if av > bv {
				return 1
			}
			return -1
		}
		if bv, ok := b.(int); ok {
			return compareValues(av, float64(bv))
		}
	}
	return 0
}

func parseBool(s string) (bool, error) {
	return strings.ToLower(s) == "true", nil
}

func parseInt(s string) (int, error) {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*8 + int(c-'0')
		}
	}
	return result, nil
}
