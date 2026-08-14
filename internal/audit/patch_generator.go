package audit

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type PatchGenerator struct {
	api        *core.API
	policy     *core.AuditPolicy
	config     *core.AuditConfig
	patchPolicy *core.PatchPolicy
}

func NewPatchGenerator(api *core.API, policy *core.AuditPolicy, config *core.AuditConfig) *PatchGenerator {
	pp := config.PatchPolicy
	if pp == nil {
		pp = DefaultPatchPolicy()
	}
	return &PatchGenerator{
		api:        api,
		policy:     policy,
		config:     config,
		patchPolicy: pp,
	}
}

func DefaultPatchPolicy() *core.PatchPolicy {
	return &core.PatchPolicy{
		DefaultMaxLength: 256,
		NumericRanges: map[string]*core.NumericRangeConfig{
			"page":     {Minimum: 1, Maximum: 1000},
			"limit":    {Minimum: 1, Maximum: 100},
			"offset":   {Minimum: 0, Maximum: 10000},
			"per_page": {Minimum: 1, Maximum: 100},
			"size":     {Minimum: 1, Maximum: 100},
			"count":    {Minimum: 0, Maximum: 10000},
			"id":       {Minimum: 1, Maximum: 999999999},
			"timeout":  {Minimum: 0, Maximum: 300},
			"default":  {Minimum: 0, Maximum: 999999},
		},
		ErrorResponseSchema: &core.ErrorResponseSchemaConfig{
			ErrorCodeField: "error_code",
			ErrorCodeType:  "string",
			MessageField:   "message",
			MessageType:    "string",
		},
	}
}

func (pg *PatchGenerator) GeneratePatches(findings []*core.AuditFinding) []*core.FixPatch {
	patches := make([]*core.FixPatch, 0)
	for _, finding := range findings {
		if !finding.IsStatic {
			continue
		}
		patch := pg.generatePatchForFinding(finding)
		if patch != nil {
			patches = append(patches, patch)
		}
	}
	pg.sortByPriority(patches)
	pg.detectConflicts(patches)
	pg.detectDependencies(patches)
	return patches
}

func (pg *PatchGenerator) generatePatchForFinding(f *core.AuditFinding) *core.FixPatch {
	switch f.RuleID {
	case "ERROR-001":
		return pg.generateMissing4xxResponsePatch(f)
	case "ERROR-002":
		return pg.generateMissing5xxResponsePatch(f)
	case "INPUT-002":
		return pg.generateMissingMaxLengthPatch(f)
	case "INPUT-003":
		return pg.generateMissingMinMaxPatch(f)
	case "DATA-003":
		return pg.generateMissingPaginationPatch(f)
	case "VERSION-001":
		return pg.generateMissingVersionPatch(f)
	case "AUTH-002", "AUTH-003":
		return pg.generateMissingSecurityPatch(f)
	default:
		return nil
	}
}

func (pg *PatchGenerator) generateMissing4xxResponsePatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	method := strings.ToLower(f.Method)
	if path == "" || method == "" {
		return nil
	}

	jsonPointer := buildPathToResponses(path, method)
	errorSchema := pg.buildErrorSchema()
	ops := []core.PatchOperation{
		{
			Op:   "add",
			Path: jsonPointer + "/400",
			Value: map[string]interface{}{
				"description": "Bad Request",
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": errorSchema,
					},
				},
			},
		},
		{
			Op:   "add",
			Path: jsonPointer + "/401",
			Value: map[string]interface{}{
				"description": "Unauthorized",
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": errorSchema,
					},
				},
			},
		},
		{
			Op:   "add",
			Path: jsonPointer + "/403",
			Value: map[string]interface{}{
				"description": "Forbidden",
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": errorSchema,
					},
				},
			},
		},
		{
			Op:   "add",
			Path: jsonPointer + "/404",
			Value: map[string]interface{}{
				"description": "Not Found",
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": errorSchema,
					},
				},
			},
		},
	}

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add standard 4xx error responses to %s %s", f.Method, path),
		Severity:    f.Severity,
		Endpoints:   []string{fmt.Sprintf("%s %s", f.Method, path)},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity),
	}
}

func (pg *PatchGenerator) generateMissing5xxResponsePatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	method := strings.ToLower(f.Method)
	if path == "" || method == "" {
		return nil
	}

	jsonPointer := buildPathToResponses(path, method)
	errorSchema := pg.buildErrorSchema()
	ops := []core.PatchOperation{
		{
			Op:   "add",
			Path: jsonPointer + "/500",
			Value: map[string]interface{}{
				"description": "Internal Server Error",
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": errorSchema,
					},
				},
			},
		},
	}

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add standard 5xx error response to %s %s", f.Method, path),
		Severity:    f.Severity,
		Endpoints:   []string{fmt.Sprintf("%s %s", f.Method, path)},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity),
	}
}

func (pg *PatchGenerator) generateMissingMaxLengthPatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	method := strings.ToLower(f.Method)
	paramName, _ := f.Evidence["param_name"].(string)
	paramLocation := fmt.Sprintf("%v", f.Evidence["param_location"])
	if path == "" || method == "" || paramName == "" {
		return nil
	}

	maxLength := pg.patchPolicy.DefaultMaxLength
	schemaPath := pg.findParamSchemaPath(path, method, paramName, paramLocation)
	if schemaPath == "" {
		return nil
	}

	ops := []core.PatchOperation{
		{
			Op:    "add",
			Path:  schemaPath + "/maxLength",
			Value: maxLength,
		},
	}

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add maxLength=%d to string parameter '%s' in %s %s", maxLength, paramName, f.Method, path),
		Severity:    f.Severity,
		Endpoints:   []string{fmt.Sprintf("%s %s", f.Method, path)},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity),
	}
}

func (pg *PatchGenerator) generateMissingMinMaxPatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	method := strings.ToLower(f.Method)
	paramName, _ := f.Evidence["param_name"].(string)
	paramLocation := fmt.Sprintf("%v", f.Evidence["param_location"])
	hasMinimum, _ := f.Evidence["has_minimum"].(bool)
	if path == "" || method == "" || paramName == "" {
		return nil
	}

	schemaPath := pg.findParamSchemaPath(path, method, paramName, paramLocation)
	if schemaPath == "" {
		return nil
	}

	minVal, maxVal := pg.inferNumericRange(paramName)
	ops := []core.PatchOperation{}

	if !hasMinimum {
		ops = append(ops, core.PatchOperation{
			Op:    "add",
			Path:  schemaPath + "/minimum",
			Value: minVal,
		})
	}
	ops = append(ops, core.PatchOperation{
		Op:    "add",
		Path:  schemaPath + "/maximum",
		Value: maxVal,
	})

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add minimum=%v/maximum=%v to numeric parameter '%s' in %s %s", minVal, maxVal, paramName, f.Method, path),
		Severity:    f.Severity,
		Endpoints:   []string{fmt.Sprintf("%s %s", f.Method, path)},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity),
	}
}

func (pg *PatchGenerator) findParamSchemaPath(path, method, paramName, paramLocation string) string {
	methods, ok := pg.api.Paths[path]
	if !ok {
		return ""
	}
	op, ok := methods[method]
	if !ok || op == nil {
		return ""
	}

	for i, param := range op.Parameters {
		if param.Name == paramName && string(param.Location) == paramLocation {
			return buildPathToOperation(path, method) + fmt.Sprintf("/parameters/%d/schema", i)
		}
	}

	return ""
}

func (pg *PatchGenerator) generateMissingPaginationPatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	method := strings.ToLower(f.Method)
	if path == "" || method == "" {
		return nil
	}

	paramsPath := buildPathToOperation(path, method) + "/parameters"
	ops := []core.PatchOperation{
		{
			Op:   "add",
			Path: paramsPath + "/-",
			Value: map[string]interface{}{
				"name":        "limit",
				"in":          "query",
				"description": "Maximum number of items to return",
				"required":    false,
				"schema": map[string]interface{}{
					"type":    "integer",
					"minimum": 1,
					"maximum": 100,
					"default": 20,
				},
			},
		},
		{
			Op:   "add",
			Path: paramsPath + "/-",
			Value: map[string]interface{}{
				"name":        "offset",
				"in":          "query",
				"description": "Number of items to skip",
				"required":    false,
				"schema": map[string]interface{}{
					"type":    "integer",
					"minimum": 0,
					"default": 0,
				},
			},
		},
	}

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add limit and offset pagination parameters to %s %s", f.Method, path),
		Severity:    f.Severity,
		Endpoints:   []string{fmt.Sprintf("%s %s", f.Method, path)},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity),
	}
}

func (pg *PatchGenerator) generateMissingVersionPatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	if path == "" {
		return nil
	}

	newPath := "/v1" + path
	ops := []core.PatchOperation{
		{
			Op:   "move",
			Path: "/paths/" + escapeJSONPointerSegment(newPath),
			From: "/paths/" + escapeJSONPointerSegment(path),
		},
	}

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add /v1 version prefix to path %s -> %s", path, newPath),
		Severity:    f.Severity,
		Endpoints:   []string{path},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity) + 10,
	}
}

func (pg *PatchGenerator) generateMissingSecurityPatch(f *core.AuditFinding) *core.FixPatch {
	path := f.Endpoint
	method := strings.ToLower(f.Method)
	if path == "" || method == "" {
		return nil
	}

	opPath := buildPathToOperation(path, method)
	ops := []core.PatchOperation{}

	schemeExists := false
	if pg.api.Components != nil && pg.api.Components.SecuritySchemes != nil {
		for _, ss := range pg.api.Components.SecuritySchemes {
			if ss.Type == "http" && ss.Scheme == "bearer" {
				schemeExists = true
				break
			}
		}
	}

	if !schemeExists {
		ops = append(ops, core.PatchOperation{
			Op:   "add",
			Path: "/components/securitySchemes/BearerAuth",
			Value: map[string]interface{}{
				"type":         "http",
				"scheme":       "bearer",
				"bearerFormat": "JWT",
			},
		})
	}

	ops = append(ops, core.PatchOperation{
		Op:   "add",
		Path: opPath + "/security",
		Value: []interface{}{
			map[string]interface{}{
				"BearerAuth": []interface{}{},
			},
		},
	})

	return &core.FixPatch{
		ID:          core.GenerateID(),
		RuleID:      f.RuleID,
		RuleTitle:   f.Title,
		Description: fmt.Sprintf("Add Bearer authentication security requirement to %s %s", f.Method, path),
		Severity:    f.Severity,
		Endpoints:   []string{fmt.Sprintf("%s %s", f.Method, path)},
		Operations:  ops,
		GeneratedAt: time.Now(),
		Priority:    severityToPriority(f.Severity),
	}
}

func (pg *PatchGenerator) buildErrorSchema() map[string]interface{} {
	cfg := pg.patchPolicy.ErrorResponseSchema
	if cfg == nil {
		cfg = DefaultPatchPolicy().ErrorResponseSchema
	}

	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			cfg.ErrorCodeField: map[string]interface{}{
				"type":        cfg.ErrorCodeType,
				"description": "Machine-readable error code",
			},
			cfg.MessageField: map[string]interface{}{
				"type":        cfg.MessageType,
				"description": "Human-readable error message",
			},
		},
		"required": []string{cfg.ErrorCodeField, cfg.MessageField},
	}
}

func (pg *PatchGenerator) inferNumericRange(paramName string) (float64, float64) {
	lower := strings.ToLower(paramName)

	if rangeConfig, ok := pg.patchPolicy.NumericRanges[lower]; ok {
		return rangeConfig.Minimum, rangeConfig.Maximum
	}

	for pattern, rangeConfig := range pg.patchPolicy.NumericRanges {
		if strings.Contains(lower, pattern) {
			return rangeConfig.Minimum, rangeConfig.Maximum
		}
	}

	defaultRange := pg.patchPolicy.NumericRanges["default"]
	if defaultRange != nil {
		return defaultRange.Minimum, defaultRange.Maximum
	}

	return 0, 999999
}

func (pg *PatchGenerator) detectConflicts(patches []*core.FixPatch) {
	pathOwners := make(map[string]string)
	pathOwnerPriority := make(map[string]int)
	pathOwnerOp := make(map[string]core.PatchOperation)

	for _, p := range patches {
		for _, op := range p.Operations {
			normalizedPath := op.Path
			if op.Op == "move" {
				normalizedPath = op.From
			}

			ownerID, exists := pathOwners[normalizedPath]
			if !exists {
				pathOwners[normalizedPath] = p.ID
				pathOwnerPriority[normalizedPath] = p.Priority
				pathOwnerOp[normalizedPath] = op
			} else if ownerID != p.ID {
				existingOp := pathOwnerOp[normalizedPath]
				if existingOp.Op == "add" && op.Op == "add" &&
					deepEqual(existingOp.Value, op.Value) {
					continue
				}

				existingPriority := pathOwnerPriority[normalizedPath]
				humanPath := unescapeJSONPointerHuman(normalizedPath)
				if p.Priority > existingPriority {
					continue
				} else if p.Priority == existingPriority {
					p.HasConflict = true
					p.ConflictReason = fmt.Sprintf("Path %s modified by multiple patches with same priority (conflicts with patch %s)", humanPath, ownerID)
				} else {
					p.HasConflict = true
					p.ConflictReason = fmt.Sprintf("Path %s already modified by higher-priority patch %s", humanPath, ownerID)
				}
			}
		}
	}
}

func (pg *PatchGenerator) detectDependencies(patches []*core.FixPatch) {
	pathCreators := make(map[string]string)
	for _, p := range patches {
		for _, op := range p.Operations {
			if op.Op == "add" || op.Op == "move" {
				pathCreators[op.Path] = p.ID
			}
		}
	}

	for _, p := range patches {
		for _, op := range p.Operations {
			if op.Op != "add" && op.Op != "move" {
				parentPath := op.Path
				lastSlash := strings.LastIndex(parentPath, "/")
				if lastSlash > 0 {
					containerPath := parentPath[:lastSlash]
					if creatorID, ok := pathCreators[containerPath]; ok && creatorID != p.ID {
						p.Dependencies = append(p.Dependencies, creatorID)
					}
				}
			}
		}
		if len(p.Dependencies) > 0 {
			seen := make(map[string]bool)
			unique := make([]string, 0)
			for _, dep := range p.Dependencies {
				if !seen[dep] {
					seen[dep] = true
					unique = append(unique, dep)
				}
			}
			p.Dependencies = unique
		}
	}
}

func (pg *PatchGenerator) sortByPriority(patches []*core.FixPatch) {
	sortPatchesByPriority(patches)
}

func sortPatchesByPriority(patches []*core.FixPatch) {
	for i := 0; i < len(patches); i++ {
		for j := i + 1; j < len(patches); j++ {
			if patches[i].Priority < patches[j].Priority {
				patches[i], patches[j] = patches[j], patches[i]
			}
		}
	}
}

func severityToPriority(sev core.Severity) int {
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

func buildPathToOperation(path, method string) string {
	return "/paths/" + escapeJSONPointerSegment(path) + "/" + escapeJSONPointerSegment(method)
}

func buildPathToResponses(path, method string) string {
	return buildPathToOperation(path, method) + "/responses"
}

func escapeJSONPointerSegment(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

func escapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

func FilterPatchesByRules(patches []*core.FixPatch, ruleIDs []string) []*core.FixPatch {
	ruleSet := make(map[string]bool)
	for _, id := range ruleIDs {
		ruleSet[strings.TrimSpace(id)] = true
	}
	filtered := make([]*core.FixPatch, 0)
	for _, p := range patches {
		if ruleSet[p.RuleID] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func GetNonConflictingPatches(patches []*core.FixPatch) []*core.FixPatch {
	result := make([]*core.FixPatch, 0)
	for _, p := range patches {
		if !p.HasConflict {
			result = append(result, p)
		}
	}
	return result
}

func ResolvePatchOrder(patches []*core.FixPatch) []*core.FixPatch {
	sortPatchesByPriority(patches)

	scheduled := make(map[string]bool)
	result := make([]*core.FixPatch, 0, len(patches))
	remaining := make([]*core.FixPatch, len(patches))
	copy(remaining, patches)

	for len(result) < len(patches) {
		progress := false
		newRemaining := make([]*core.FixPatch, 0)

		for _, p := range remaining {
			allDepsMet := true
			for _, depID := range p.Dependencies {
				if !scheduled[depID] {
					allDepsMet = false
					break
				}
			}
			if allDepsMet {
				result = append(result, p)
				scheduled[p.ID] = true
				progress = true
			} else {
				newRemaining = append(newRemaining, p)
			}
		}

		if !progress {
			for _, p := range newRemaining {
				result = append(result, p)
			}
			break
		}
		remaining = newRemaining
	}

	return result
}

func deepEqual(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}
