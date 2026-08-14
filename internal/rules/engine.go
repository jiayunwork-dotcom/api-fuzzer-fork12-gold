package rules

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"gopkg.in/yaml.v3"
)

type RuleConfig struct {
	Payloads  map[string][]interface{} `yaml:"payloads"`
	Detectors []DetectorRule          `yaml:"detectors"`
	Excludes  []string                 `yaml:"excludes"`
	Mutators  []MutatorRule           `yaml:"mutators"`
}

type DetectorRule struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

type MutatorRule struct {
	Name        string   `yaml:"name"`
	TargetTypes []string `yaml:"target_types"`
	Mutation    string   `yaml:"mutation"`
}

type RuleEngine struct {
	config      RuleConfig
	detectors   []*compiledDetector
	rand        *rand.Rand
}

type compiledDetector struct {
	rule    DetectorRule
	pattern *regexp.Regexp
}

func NewRuleEngine(randSeed int64) *RuleEngine {
	return &RuleEngine{
		rand: rand.New(rand.NewSource(randSeed)),
	}
}

func (e *RuleEngine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var cfg RuleConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	return e.Load(cfg)
}

func (e *RuleEngine) Load(cfg RuleConfig) error {
	e.config = cfg

	for _, d := range cfg.Detectors {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex in detector '%s': %w", d.Name, err)
		}
		e.detectors = append(e.detectors, &compiledDetector{
			rule:    d,
			pattern: re,
		})
	}

	return nil
}

func (e *RuleEngine) GetCustomPayloads(typeName string) []interface{} {
	if e.config.Payloads == nil {
		return nil
	}
	return e.config.Payloads[typeName]
}

func (e *RuleEngine) IsExcludedEndpoint(path string) bool {
	for _, pattern := range e.config.Excludes {
		if matchGlob(pattern, path) {
			return true
		}
	}
	return false
}

func (e *RuleEngine) IsExcludedParam(paramName string) bool {
	for _, pattern := range e.config.Excludes {
		if matchGlob(pattern, paramName) {
			return true
		}
	}
	return false
}

func (e *RuleEngine) CheckDetectors(body string) []*core.Issue {
	var issues []*core.Issue

	for _, d := range e.detectors {
		if d.pattern.MatchString(body) {
			matches := d.pattern.FindAllString(body, -1)
			if len(matches) > 0 {
				matchSample := strings.Join(matches[:3], ", ")
				issues = append(issues, &core.Issue{
					ID:          core.GenerateID(),
					Severity:    core.Severity(d.rule.Severity),
					Type:        core.IssueTypeCustom,
					Title:       "Custom Rule: " + d.rule.Name,
					Description: d.rule.Description + ": " + matchSample,
				})
			}
		}
	}

	return issues
}

func (e *RuleEngine) MutateValue(value interface{}, typeName string) interface{} {
	if len(e.config.Mutators) == 0 {
		return value
	}

	var applicableMutators []MutatorRule
	for _, m := range e.config.Mutators {
		if len(m.TargetTypes) == 0 {
			applicableMutators = append(applicableMutators, m)
			continue
		}
		for _, t := range m.TargetTypes {
			if t == typeName {
				applicableMutators = append(applicableMutators, m)
				break
			}
		}
	}

	if len(applicableMutators) == 0 {
		return value
	}

	mutator := applicableMutators[e.rand.Intn(len(applicableMutators))]
	return e.applyMutation(value, mutator.Mutation)
}

func (e *RuleEngine) MutateJSON(jsonStr string) (string, error) {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr, nil
	}

	mutated := e.mutateObject(data)
	result, err := json.Marshal(mutated)
	if err != nil {
		return jsonStr, nil
	}
	return string(result), nil
}

func (e *RuleEngine) mutateObject(data interface{}) interface{} {
	switch obj := data.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}

		if len(keys) > 0 && e.rand.Float32() < 0.3 {
			deleteKey := keys[e.rand.Intn(len(keys))]
			delete(obj, deleteKey)
		}

		for k, v := range obj {
			obj[k] = e.mutateObject(v)
		}

		if e.rand.Float32() < 0.2 {
			obj["__mutated_field__"] = e.generateRandomValue()
		}

		return obj

	case []interface{}:
		for i, v := range obj {
			obj[i] = e.mutateObject(v)
		}

		if len(obj) > 0 && e.rand.Float32() < 0.3 {
			idx := e.rand.Intn(len(obj))
			obj[idx] = e.generateRandomValue()
		}

		return obj

	case string:
		if e.rand.Float32() < 0.2 {
			return obj + "_mutated"
		}
		return obj

	default:
		return data
	}
}

func (e *RuleEngine) generateRandomValue() interface{} {
	switch e.rand.Intn(4) {
	case 0:
		return e.rand.Intn(1000000)
	case 1:
		return core.GenerateRandomString(10)
	case 2:
		return e.rand.Float64() * 1000
	default:
		return true
	}
}

func (e *RuleEngine) applyMutation(value interface{}, mutationType string) interface{} {
	switch mutationType {
	case "truncate":
		if s, ok := value.(string); ok && len(s) > 0 {
			return s[:len(s)/2]
		}
	case "append_garbage":
		if s, ok := value.(string); ok {
			return s + "_" + core.GenerateRandomString(5)
		}
	case "flip_bit":
		if i, ok := value.(int); ok {
			return i ^ 0xFF
		}
	case "null":
		return nil
	case "empty":
		return ""
	}
	return value
}

func matchGlob(pattern, str string) bool {
	if pattern == str {
		return true
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return false
	}

	for i, part := range parts {
		if i == 0 {
			if !strings.HasPrefix(str, part) {
				return false
			}
		} else if i == len(parts)-1 {
			if !strings.HasPrefix(str, part) {
				return false
			}
		} else {
			if !strings.Contains(str, part) {
				return false
			}
		}
	}

	return true
}

func (e *RuleEngine) MergeIntoFuzzConfig(fuzzConfig *core.FuzzConfig) {
	if e.config.Payloads != nil && fuzzConfig.CustomPayloads == nil {
		fuzzConfig.CustomPayloads = make(map[string][]interface{})
	}
	for k, v := range e.config.Payloads {
		fuzzConfig.CustomPayloads[k] = append(fuzzConfig.CustomPayloads[k], v...)
	}

	fuzzConfig.ExcludeEndpoints = append(fuzzConfig.ExcludeEndpoints, e.config.Excludes...)
}

func LoadRuleConfig(path string) (*RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg RuleConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
