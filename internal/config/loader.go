package config

import (
	"fmt"
	"os"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"gopkg.in/yaml.v3"
)

type YAMLConfig struct {
	Target struct {
		URL         string `yaml:"url"`
		OpenAPISpec string `yaml:"openapi_spec"`
		Timeout     string `yaml:"timeout"`
	} `yaml:"target"`

	Auth struct {
		Type              string   `yaml:"type"`
		BearerToken       string   `yaml:"bearer_token"`
		BearerTokenEnv    string   `yaml:"bearer_token_env"`
		APIKey            string   `yaml:"api_key"`
		APIKeyEnv         string   `yaml:"api_key_env"`
		APIKeyName        string   `yaml:"api_key_name"`
		APIKeyIn          string   `yaml:"api_key_in"`
		BasicAuthUser     string   `yaml:"basic_auth_user"`
		BasicAuthPass     string   `yaml:"basic_auth_pass"`
		BasicAuthPassEnv  string   `yaml:"basic_auth_pass_env"`
		OAuthClientID     string   `yaml:"oauth_client_id"`
		OAuthClientSecret string   `yaml:"oauth_client_secret"`
		OAuthTokenURL     string   `yaml:"oauth_token_url"`
		OAuthScopes       []string `yaml:"oauth_scopes"`
	} `yaml:"auth"`

	RateLimit struct {
		QPS               int    `yaml:"qps"`
		Concurrency       int    `yaml:"concurrency"`
		RequestInterval   string `yaml:"request_interval"`
		Adaptive          bool   `yaml:"adaptive"`
		ProgressiveStress bool   `yaml:"progressive_stress"`
	} `yaml:"rate_limit"`

	Analyzer struct {
		TimeoutThreshold     string          `yaml:"timeout_threshold"`
		MaxResponseBodySize  int64           `yaml:"max_response_body_size"`
		InfoLeakPatterns     []string        `yaml:"info_leak_patterns"`
		CustomPatterns       []CustomPattern `yaml:"custom_patterns"`
		MaxConsecutiveTimeouts int           `yaml:"max_consecutive_timeouts"`
	} `yaml:"analyzer"`

	Fuzz struct {
		Seed              int64              `yaml:"seed"`
		MaxTestCases      int                `yaml:"max_test_cases"`
		MaxDepth          int                `yaml:"max_depth"`
		GenerateBoundary  bool               `yaml:"generate_boundary"`
		GenerateMalicious bool               `yaml:"generate_malicious"`
		Stateful          bool               `yaml:"stateful"`
		ExcludeEndpoints  []string           `yaml:"exclude_endpoints"`
		ExcludeParams     []string           `yaml:"exclude_params"`
		CustomPayloads    map[string][]interface{} `yaml:"custom_payloads"`
	} `yaml:"fuzz"`

	Reporter struct {
		OutputFormats []string `yaml:"output_formats"`
		OutputDir     string   `yaml:"output_dir"`
		FailOn        string   `yaml:"fail_on"`
		BaselineFile  string   `yaml:"baseline_file"`
	} `yaml:"reporter"`

	Rules struct {
		Payloads  map[string][]interface{} `yaml:"payloads"`
		Detectors []CustomPattern          `yaml:"detectors"`
		Excludes  []string                 `yaml:"excludes"`
	} `yaml:"rules"`
}

type CustomPattern struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

func DefaultConfig() *core.Config {
	return &core.Config{
		RateLimit: core.RateLimitConfig{
			QPS:               10,
			Concurrency:       5,
			RequestInterval:   100 * time.Millisecond,
			Adaptive:          true,
			ProgressiveStress: false,
			Timeout:           30 * time.Second,
		},
		Analyzer: core.AnalyzerConfig{
			TimeoutThreshold:   10 * time.Second,
			MaxResponseBodySize: 10 * 1024,
			InfoLeakPatterns:   DefaultInfoLeakPatterns(),
		},
		Fuzz: core.FuzzConfig{
			Seed:              time.Now().UnixNano(),
			MaxTestCases:      1000,
			MaxDepth:          10,
			GenerateBoundary:  true,
			GenerateMalicious: true,
			Stateful:          true,
		},
		Reporter: core.ReporterConfig{
			OutputFormats: []string{"terminal", "json"},
			OutputDir:     "./reports",
			Terminal:      true,
			JSON:          true,
			FailOn:        core.SeverityHigh,
		},
		Timeout:                30 * time.Minute,
		MaxConsecutiveTimeouts: 5,
	}
}

func DefaultInfoLeakPatterns() []string {
	return []string{
		`(?i)stack trace`,
		`(?i)stacktrace`,
		`(?i)traceback`,
		`(?i)exception`,
		`(?i)fatal error`,
		`(?i)mysql`,
		`(?i)postgres`,
		`(?i)ora-\d+`,
		`(?i)sql syntax`,
		`(?i)undefined index`,
		`(?i)warning:`,
		`(?i)notice:`,
		`(?i)file not found`,
		`(?i)line \d+`,
		`(?i)in \/[^ ]+ on line`,
		`(?i)server: .+\/\d+\.\d+`,
		`(?i)x-powered-by:`,
		`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
		`(?i)internal error`,
		`(?i)could not connect`,
		`(?i)connection refused`,
		`(?i)access denied`,
		`(?i)permission denied`,
	}
}

func LoadConfig(path string) (*core.Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		var yamlCfg YAMLConfig
		if err := yaml.Unmarshal(data, &yamlCfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		mergeYAMLConfig(cfg, &yamlCfg)
	}

	if envToken := os.Getenv("API_FUZZER_BEARER_TOKEN"); envToken != "" {
		cfg.Auth.BearerToken = envToken
	}
	if envAPIKey := os.Getenv("API_FUZZER_API_KEY"); envAPIKey != "" {
		cfg.Auth.APIKey = envAPIKey
	}
	if envPass := os.Getenv("API_FUZZER_BASIC_PASS"); envPass != "" {
		cfg.Auth.BasicAuthPass = envPass
	}
	if envOAuthSecret := os.Getenv("API_FUZZER_OAUTH_SECRET"); envOAuthSecret != "" {
		cfg.Auth.OAuthClientSecret = envOAuthSecret
	}

	return cfg, nil
}

func ValidateConfig(cfg *core.Config) error {
	return validateConfig(cfg)
}

func mergeYAMLConfig(cfg *core.Config, yamlCfg *YAMLConfig) {
	if yamlCfg.Target.URL != "" {
		cfg.TargetURL = yamlCfg.Target.URL
	}
	if yamlCfg.Target.OpenAPISpec != "" {
		cfg.OpenAPISpec = yamlCfg.Target.OpenAPISpec
	}
	if yamlCfg.Target.Timeout != "" {
		if d, err := time.ParseDuration(yamlCfg.Target.Timeout); err == nil {
			cfg.Timeout = d
		}
	}

	cfg.Auth.Type = yamlCfg.Auth.Type
	cfg.Auth.BearerToken = getEnvOrValue(yamlCfg.Auth.BearerTokenEnv, yamlCfg.Auth.BearerToken)
	cfg.Auth.APIKey = getEnvOrValue(yamlCfg.Auth.APIKeyEnv, yamlCfg.Auth.APIKey)
	cfg.Auth.APIKeyName = yamlCfg.Auth.APIKeyName
	cfg.Auth.APIKeyIn = yamlCfg.Auth.APIKeyIn
	cfg.Auth.BasicAuthUser = yamlCfg.Auth.BasicAuthUser
	cfg.Auth.BasicAuthPass = getEnvOrValue(yamlCfg.Auth.BasicAuthPassEnv, yamlCfg.Auth.BasicAuthPass)
	cfg.Auth.OAuthClientID = yamlCfg.Auth.OAuthClientID
	cfg.Auth.OAuthClientSecret = yamlCfg.Auth.OAuthClientSecret
	cfg.Auth.OAuthTokenURL = yamlCfg.Auth.OAuthTokenURL
	cfg.Auth.OAuthScopes = yamlCfg.Auth.OAuthScopes

	if yamlCfg.RateLimit.QPS > 0 {
		cfg.RateLimit.QPS = yamlCfg.RateLimit.QPS
	}
	if yamlCfg.RateLimit.Concurrency > 0 {
		cfg.RateLimit.Concurrency = yamlCfg.RateLimit.Concurrency
	}
	if yamlCfg.RateLimit.RequestInterval != "" {
		if d, err := time.ParseDuration(yamlCfg.RateLimit.RequestInterval); err == nil {
			cfg.RateLimit.RequestInterval = d
		}
	}
	cfg.RateLimit.Adaptive = yamlCfg.RateLimit.Adaptive
	cfg.RateLimit.ProgressiveStress = yamlCfg.RateLimit.ProgressiveStress

	if yamlCfg.Analyzer.TimeoutThreshold != "" {
		if d, err := time.ParseDuration(yamlCfg.Analyzer.TimeoutThreshold); err == nil {
			cfg.Analyzer.TimeoutThreshold = d
		}
	}
	if yamlCfg.Analyzer.MaxResponseBodySize > 0 {
		cfg.Analyzer.MaxResponseBodySize = yamlCfg.Analyzer.MaxResponseBodySize
	}
	if len(yamlCfg.Analyzer.InfoLeakPatterns) > 0 {
		cfg.Analyzer.InfoLeakPatterns = append(cfg.Analyzer.InfoLeakPatterns, yamlCfg.Analyzer.InfoLeakPatterns...)
	}
	for _, p := range yamlCfg.Analyzer.CustomPatterns {
		cfg.Analyzer.CustomPatterns = append(cfg.Analyzer.CustomPatterns, core.CustomPattern{
			Name:        p.Name,
			Pattern:     p.Pattern,
			Severity:    core.Severity(p.Severity),
			Description: p.Description,
		})
	}
	if yamlCfg.Analyzer.MaxConsecutiveTimeouts > 0 {
		cfg.MaxConsecutiveTimeouts = yamlCfg.Analyzer.MaxConsecutiveTimeouts
	}

	if yamlCfg.Fuzz.Seed != 0 {
		cfg.Fuzz.Seed = yamlCfg.Fuzz.Seed
	}
	if yamlCfg.Fuzz.MaxTestCases > 0 {
		cfg.Fuzz.MaxTestCases = yamlCfg.Fuzz.MaxTestCases
	}
	if yamlCfg.Fuzz.MaxDepth > 0 {
		cfg.Fuzz.MaxDepth = yamlCfg.Fuzz.MaxDepth
	}
	cfg.Fuzz.GenerateBoundary = yamlCfg.Fuzz.GenerateBoundary
	cfg.Fuzz.GenerateMalicious = yamlCfg.Fuzz.GenerateMalicious
	cfg.Fuzz.Stateful = yamlCfg.Fuzz.Stateful
	cfg.Fuzz.ExcludeEndpoints = yamlCfg.Fuzz.ExcludeEndpoints
	cfg.Fuzz.ExcludeParams = yamlCfg.Fuzz.ExcludeParams
	if yamlCfg.Fuzz.CustomPayloads != nil {
		if cfg.Fuzz.CustomPayloads == nil {
			cfg.Fuzz.CustomPayloads = make(map[string][]interface{})
		}
		for k, v := range yamlCfg.Fuzz.CustomPayloads {
			cfg.Fuzz.CustomPayloads[k] = v
		}
	}

	if len(yamlCfg.Reporter.OutputFormats) > 0 {
		cfg.Reporter.OutputFormats = yamlCfg.Reporter.OutputFormats
		for _, f := range yamlCfg.Reporter.OutputFormats {
			switch f {
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
	if yamlCfg.Reporter.OutputDir != "" {
		cfg.Reporter.OutputDir = yamlCfg.Reporter.OutputDir
	}
	if yamlCfg.Reporter.FailOn != "" {
		cfg.Reporter.FailOn = core.Severity(yamlCfg.Reporter.FailOn)
	}
	if yamlCfg.Reporter.BaselineFile != "" {
		cfg.Reporter.BaselineFile = yamlCfg.Reporter.BaselineFile
	}

	if yamlCfg.Rules.Payloads != nil {
		if cfg.Fuzz.CustomPayloads == nil {
			cfg.Fuzz.CustomPayloads = make(map[string][]interface{})
		}
		for k, v := range yamlCfg.Rules.Payloads {
			cfg.Fuzz.CustomPayloads[k] = v
		}
	}
	for _, p := range yamlCfg.Rules.Detectors {
		cfg.Analyzer.CustomPatterns = append(cfg.Analyzer.CustomPatterns, core.CustomPattern{
			Name:        p.Name,
			Pattern:     p.Pattern,
			Severity:    core.Severity(p.Severity),
			Description: p.Description,
		})
	}
	for _, e := range yamlCfg.Rules.Excludes {
		if !core.ContainsString(cfg.Fuzz.ExcludeEndpoints, e) {
			cfg.Fuzz.ExcludeEndpoints = append(cfg.Fuzz.ExcludeEndpoints, e)
		}
	}
}

func getEnvOrValue(envKey, value string) string {
	if envKey != "" {
		if envVal := os.Getenv(envKey); envVal != "" {
			return envVal
		}
	}
	return value
}

func validateConfig(cfg *core.Config) error {
	if cfg.OpenAPISpec == "" {
		return fmt.Errorf("openapi spec path is required")
	}

	if cfg.RateLimit.QPS < 0 {
		return fmt.Errorf("qps cannot be negative")
	}
	if cfg.RateLimit.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}

	validSeverities := map[core.Severity]bool{
		core.SeverityCritical: true,
		core.SeverityHigh:     true,
		core.SeverityMedium:   true,
		core.SeverityLow:      true,
		core.SeverityInfo:     true,
	}
	if !validSeverities[cfg.Reporter.FailOn] {
		return fmt.Errorf("invalid fail_on severity: %s", cfg.Reporter.FailOn)
	}

	return nil
}
