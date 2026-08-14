package audit

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"gopkg.in/yaml.v3"
)

type YAMLPolicy struct {
	Rules struct {
		Enabled  []string            `yaml:"enabled"`
		Disabled []string            `yaml:"disabled"`
		Severity map[string]string   `yaml:"severity"`
	} `yaml:"rules"`

	SensitiveFields struct {
		Custom []string `yaml:"custom"`
	} `yaml:"sensitive_fields"`

	Exclude struct {
		Paths []string `yaml:"paths"`
	} `yaml:"exclude"`

	CustomRules []struct {
		ID            string                 `yaml:"id"`
		Category      string                 `yaml:"category"`
		Severity      string                 `yaml:"severity"`
		Title         string                 `yaml:"title"`
		Description   string                 `yaml:"description"`
		JSONPath      string                 `yaml:"jsonpath"`
		Condition     map[string]interface{} `yaml:"condition"`
		FixSuggestion string                 `yaml:"fix_suggestion"`
	} `yaml:"custom_rules"`

	Patch struct {
		DefaultMaxLength int64                            `yaml:"default_max_length"`
		NumericRanges    map[string]*YAMLNumericRange     `yaml:"numeric_ranges"`
		ErrorResponse    *YAMLErrorResponseSchema         `yaml:"error_response_schema"`
	} `yaml:"patch"`
}

type YAMLNumericRange struct {
	Minimum float64 `yaml:"minimum"`
	Maximum float64 `yaml:"maximum"`
}

type YAMLErrorResponseSchema struct {
	ErrorCodeField string `yaml:"error_code_field"`
	ErrorCodeType  string `yaml:"error_code_type"`
	MessageField   string `yaml:"message_field"`
	MessageType    string `yaml:"message_type"`
}

func LoadPolicy(policyPath string) (*core.AuditPolicy, error) {
	policy := &core.AuditPolicy{
		EnabledRules:       make(map[string]bool),
		DisabledRules:      make(map[string]bool),
		CustomSeverities:   make(map[string]core.Severity),
		CustomSensitiveFields: make([]string, 0),
		ExcludedPaths:      make([]string, 0),
		CustomRules:        make([]*core.CustomAuditRule, 0),
	}

	for _, rule := range BuiltInRules {
		policy.EnabledRules[rule.ID] = rule.Enabled
	}

	if policyPath == "" {
		policy.CustomSensitiveFields = append(policy.CustomSensitiveFields, DefaultSensitiveFields...)
		return policy, nil
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var yamlPolicy YAMLPolicy
	if err := yaml.Unmarshal(data, &yamlPolicy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if len(yamlPolicy.Rules.Enabled) > 0 {
		for id := range policy.EnabledRules {
			policy.EnabledRules[id] = false
		}
		for _, id := range yamlPolicy.Rules.Enabled {
			policy.EnabledRules[id] = true
		}
	}

	for _, id := range yamlPolicy.Rules.Disabled {
		policy.EnabledRules[id] = false
		policy.DisabledRules[id] = true
	}

	for id, sev := range yamlPolicy.Rules.Severity {
		policy.CustomSeverities[id] = core.Severity(strings.ToLower(sev))
	}

	policy.CustomSensitiveFields = append(policy.CustomSensitiveFields, DefaultSensitiveFields...)
	policy.CustomSensitiveFields = append(policy.CustomSensitiveFields, yamlPolicy.SensitiveFields.Custom...)

	policy.ExcludedPaths = yamlPolicy.Exclude.Paths

	for _, cr := range yamlPolicy.CustomRules {
		customRule := &core.CustomAuditRule{
			ID:            cr.ID,
			Category:      cr.Category,
			Severity:      core.Severity(strings.ToLower(cr.Severity)),
			Title:         cr.Title,
			Description:   cr.Description,
			JSONPath:      cr.JSONPath,
			Condition:     cr.Condition,
			FixSuggestion: cr.FixSuggestion,
		}
		policy.CustomRules = append(policy.CustomRules, customRule)
		policy.EnabledRules[cr.ID] = true
	}

	LoadPatchPolicyFromYAML(&yamlPolicy)

	return policy, nil
}

func GetRuleByID(ruleID string) *core.AuditRule {
	for _, rule := range BuiltInRules {
		if rule.ID == ruleID {
			return rule
		}
	}
	return nil
}

func GetEffectiveSeverity(ruleID string, policy *core.AuditPolicy) core.Severity {
	if sev, ok := policy.CustomSeverities[ruleID]; ok {
		return sev
	}
	rule := GetRuleByID(ruleID)
	if rule != nil {
		return rule.Severity
	}
	return core.SeverityMedium
}

func IsRuleEnabled(ruleID string, policy *core.AuditPolicy, categories []string) bool {
	if enabled, ok := policy.EnabledRules[ruleID]; ok && !enabled {
		return false
	}

	if len(categories) == 0 {
		return true
	}

	rule := GetRuleByID(ruleID)
	if rule == nil {
		for _, cr := range policy.CustomRules {
			if cr.ID == ruleID {
				return core.ContainsString(categories, cr.Category)
			}
		}
		return false
	}

	return core.ContainsString(categories, rule.Category)
}

func IsPathExcluded(path string, policy *core.AuditPolicy) bool {
	for _, excluded := range policy.ExcludedPaths {
		if strings.HasPrefix(excluded, path) || path == excluded {
			return true
		}
	}
	return false
}

func GetSensitiveFieldPatterns(policy *core.AuditPolicy) []string {
	return policy.CustomSensitiveFields
}

func DefaultAuditConfig() *core.AuditConfig {
	return &core.AuditConfig{
		SeverityThreshold:   core.SeverityMedium,
		OutputDir:           "./audit-reports",
		OutputFormats:       []string{"terminal", "json"},
		Terminal:            true,
		JSON:                true,
		HTML:                false,
		EnableDynamic:       false,
		ExportPatchesFormat: "jsonpatch",
		RateLimit: core.RateLimitConfig{
			QPS:               10,
			Concurrency:       5,
			RequestInterval:   100 * time.Millisecond,
			Adaptive:          true,
			ProgressiveStress: false,
			Timeout:           30 * time.Second,
		},
	}
}

func LoadPatchPolicyFromYAML(yamlPolicy *YAMLPolicy) *core.PatchPolicy {
	pp := DefaultPatchPolicy()

	if yamlPolicy.Patch.DefaultMaxLength > 0 {
		pp.DefaultMaxLength = yamlPolicy.Patch.DefaultMaxLength
	}

	if len(yamlPolicy.Patch.NumericRanges) > 0 {
		for name, nr := range yamlPolicy.Patch.NumericRanges {
			if nr != nil {
				pp.NumericRanges[name] = &core.NumericRangeConfig{
					Minimum: nr.Minimum,
					Maximum: nr.Maximum,
				}
			}
		}
	}

	if yamlPolicy.Patch.ErrorResponse != nil {
		er := yamlPolicy.Patch.ErrorResponse
		if er.ErrorCodeField != "" {
			pp.ErrorResponseSchema.ErrorCodeField = er.ErrorCodeField
		}
		if er.ErrorCodeType != "" {
			pp.ErrorResponseSchema.ErrorCodeType = er.ErrorCodeType
		}
		if er.MessageField != "" {
			pp.ErrorResponseSchema.MessageField = er.MessageField
		}
		if er.MessageType != "" {
			pp.ErrorResponseSchema.MessageType = er.MessageType
		}
	}

	return pp
}
