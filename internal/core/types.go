package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type IssueType string

const (
	IssueType5xxError          IssueType = "5xx_error"
	IssueTypeTimeout           IssueType = "timeout"
	IssueTypeInfoLeak          IssueType = "information_leak"
	IssueTypeStackTrace        IssueType = "stack_trace"
	IssueTypeDbError           IssueType = "database_error"
	IssueTypeInconsistent      IssueType = "inconsistent_response"
	IssueTypeUnexpectedSuccess IssueType = "unexpected_success"
	IssueTypeIdor              IssueType = "idor"
	IssueTypeCustom            IssueType = "custom"
)

type ParameterLocation string

const (
	ParamLocationPath   ParameterLocation = "path"
	ParamLocationQuery  ParameterLocation = "query"
	ParamLocationHeader ParameterLocation = "header"
	ParamLocationCookie ParameterLocation = "cookie"
	ParamLocationBody   ParameterLocation = "body"
)

type Parameter struct {
	Name        string
	Location    ParameterLocation
	Description string
	Required    bool
	Deprecated  bool
	Schema      *Schema
}

type Schema struct {
	Type                 string
	Format               string
	Items                *Schema
	Properties           map[string]*Schema
	AdditionalProperties *Schema
	Required             []string
	Enum                 []interface{}
	Pattern              string
	MinLength            *int64
	MaxLength            *int64
	Minimum              *float64
	Maximum              *float64
	ExclusiveMinimum     bool
	ExclusiveMaximum     bool
	MinItems             *int64
	MaxItems             *int64
	MinProperties        *int64
	MaxProperties        *int64
	Default              interface{}
	Nullable             bool
	Description          string
	Ref                  string
}

type Operation struct {
	Method          string
	Path            string
	Summary         string
	Description     string
	OperationID     string
	Tags            []string
	Parameters      []*Parameter
	RequestBody     *RequestBody
	Responses       map[string]*Response
	Security        []map[string][]string
	Deprecated      bool
}

type RequestBody struct {
	Description string
	Required    bool
	Content     map[string]*MediaType
}

type MediaType struct {
	Schema   *Schema
	Encoding map[string]*Encoding
}

type Encoding struct {
	ContentType   string
	Headers       map[string]*Parameter
	Style         string
	Explode       bool
	AllowReserved bool
}

type Response struct {
	Description string
	Headers     map[string]*Parameter
	Content     map[string]*MediaType
}

type API struct {
	Version      string
	Title        string
	Description  string
	Servers      []Server
	Paths        map[string]map[string]*Operation
	Components   *Components
	Security     []map[string][]string
	basePath     string
}

type Server struct {
	URL         string
	Description string
	Variables   map[string]*ServerVariable
}

type ServerVariable struct {
	Enum        []string
	Default     string
	Description string
}

type Components struct {
	Schemas         map[string]*Schema
	Parameters      map[string]*Parameter
	Headers         map[string]*Parameter
	RequestBodies   map[string]*RequestBody
	Responses       map[string]*Response
	SecuritySchemes map[string]*SecurityScheme
}

type SecurityScheme struct {
	Type             string
	Description      string
	Name             string
	In               string
	Scheme           string
	BearerFormat     string
	Flows            *OAuthFlows
	OpenIDConnectURL string
}

type OAuthFlows struct {
	Implicit          *OAuthFlow
	Password          *OAuthFlow
	ClientCredentials *OAuthFlow
	AuthorizationCode *OAuthFlow
}

type OAuthFlow struct {
	AuthorizationURL string
	TokenURL         string
	RefreshURL       string
	Scopes           map[string]string
}

type TestCase struct {
	ID           string
	Seed         int64
	Operation    *Operation
	PathParams   map[string]interface{}
	QueryParams  map[string]interface{}
	HeaderParams map[string]interface{}
	CookieParams map[string]interface{}
	Body         interface{}
	ContentType  string
	Description  string
	IsStateful   bool
	DependsOn    []string
}

type HTTPRequest struct {
	Method      string
	URL         string
	Headers     map[string]string
	Cookies     map[string]string
	Body        string
	ContentType string
}

type HTTPResponse struct {
	StatusCode    int
	Status        string
	Headers       map[string]string
	Body          string
	BodyTruncated bool
	Duration      time.Duration
	Error         error
}

type Issue struct {
	ID             string
	Severity       Severity
	Type           IssueType
	Title          string
	Description    string
	Endpoint       string
	Method         string
	Requests       []*HTTPRequest
	Responses      []*HTTPResponse
	TestCaseIDs    []string
	Inputs         []string
	Fingerprint    string
	FalsePositive  bool
	CreatedAt      time.Time
}

func (i *Issue) ComputeFingerprint() {
	if i.Fingerprint != "" {
		return
	}
	var bodySample string
	if len(i.Responses) > 0 {
		body := i.Responses[0].Body
		if len(body) > 50 {
			bodySample = body[:50]
		} else {
			bodySample = body
		}
	}
	fp := fmt.Sprintf("%s|%s|%d|%s", i.Endpoint, i.Method,
		firstResponseCode(i.Responses), bodySample)
	hash := sha256.Sum256([]byte(fp))
	i.Fingerprint = hex.EncodeToString(hash[:])[:16]
}

func firstResponseCode(responses []*HTTPResponse) int {
	if len(responses) > 0 {
		return responses[0].StatusCode
	}
	return 0
}

type TestResult struct {
	TestCase   *TestCase
	Request    *HTTPRequest
	Response   *HTTPResponse
	Issues     []*Issue
	IsSuccess  bool
	IsSkipped  bool
	SkipReason string
}

type Coverage struct {
	mu sync.RWMutex

	EndpointsTested    map[string]bool
	EndpointsTotal     int
	MethodsTested      map[string]map[string]bool
	ParamsTested       map[string]map[string]map[string]bool
	ResponseCodes      map[string]map[int]bool
	SchemaFieldsTested map[string]map[string]bool
}

func NewCoverage() *Coverage {
	return &Coverage{
		EndpointsTested:    make(map[string]bool),
		MethodsTested:      make(map[string]map[string]bool),
		ParamsTested:       make(map[string]map[string]map[string]bool),
		ResponseCodes:      make(map[string]map[int]bool),
		SchemaFieldsTested: make(map[string]map[string]bool),
	}
}

func (c *Coverage) MarkEndpoint(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.EndpointsTested[path] = true
}

func (c *Coverage) MarkMethod(path, method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.MethodsTested[path]; !ok {
		c.MethodsTested[path] = make(map[string]bool)
	}
	c.MethodsTested[path][strings.ToUpper(method)] = true
}

func (c *Coverage) MarkParam(path, paramName, variant string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.ParamsTested[path]; !ok {
		c.ParamsTested[path] = make(map[string]map[string]bool)
	}
	if _, ok := c.ParamsTested[path][paramName]; !ok {
		c.ParamsTested[path][paramName] = make(map[string]bool)
	}
	c.ParamsTested[path][paramName][variant] = true
}

func (c *Coverage) MarkResponseCode(path string, code int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.ResponseCodes[path]; !ok {
		c.ResponseCodes[path] = make(map[int]bool)
	}
	c.ResponseCodes[path][code] = true
}

func (c *Coverage) MarkSchemaField(path, field string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.SchemaFieldsTested[path]; !ok {
		c.SchemaFieldsTested[path] = make(map[string]bool)
	}
	c.SchemaFieldsTested[path][field] = true
}

func (c *Coverage) EndpointCoverage() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.EndpointsTotal == 0 {
		return 0
	}
	return float64(len(c.EndpointsTested)) / float64(c.EndpointsTotal) * 100
}

type ResourceContext struct {
	mu sync.RWMutex

	CreatedResources map[string][]Resource
	Tokens           map[string]string
	Extractions      map[string]interface{}
}

type Resource struct {
	ID         string
	Type       string
	Endpoint   string
	Method     string
	Response   *HTTPResponse
	CreatedAt  time.Time
	Failed     bool
	SkipReason string
}

func NewResourceContext() *ResourceContext {
	return &ResourceContext{
		CreatedResources: make(map[string][]Resource),
		Tokens:           make(map[string]string),
		Extractions:      make(map[string]interface{}),
	}
}

func (r *ResourceContext) AddResource(resourceType string, resource Resource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.CreatedResources[resourceType] = append(r.CreatedResources[resourceType], resource)
}

func (r *ResourceContext) GetResources(resourceType string) []Resource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.CreatedResources[resourceType]
}

func (r *ResourceContext) GetLatestResource(resourceType string) *Resource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resources := r.CreatedResources[resourceType]
	if len(resources) == 0 {
		return nil
	}
	return &resources[len(resources)-1]
}

func (r *ResourceContext) SetToken(name, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Tokens[name] = value
}

func (r *ResourceContext) GetToken(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, ok := r.Tokens[name]
	return val, ok
}

func (r *ResourceContext) SetExtraction(key string, value interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Extractions[key] = value
}

func (r *ResourceContext) GetExtraction(key string) (interface{}, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, ok := r.Extractions[key]
	return val, ok
}

type DependencyNode struct {
	Operation *Operation
	DependsOn []*DependencyNode
	DependedBy []*DependencyNode
}

type DependencyGraph struct {
	Nodes map[string]*DependencyNode
}

func (g *DependencyGraph) ToDOT() string {
	var sb strings.Builder
	sb.WriteString("digraph APIDependencies {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=rounded];\n")

	for id, node := range g.Nodes {
		label := fmt.Sprintf("%s %s", node.Operation.Method, node.Operation.Path)
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\"];\n", id, label))
		for _, dep := range node.DependsOn {
			depID := fmt.Sprintf("%s %s", dep.Operation.Method, dep.Operation.Path)
			sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\";\n", depID, id))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

type AuthConfig struct {
	Type             string
	BearerToken      string
	APIKey           string
	APIKeyName       string
	APIKeyIn         string
	BasicAuthUser    string
	BasicAuthPass    string
	OAuthClientID    string
	OAuthClientSecret string
	OAuthTokenURL    string
	OAuthScopes      []string
}

type RateLimitConfig struct {
	QPS               int
	Concurrency       int
	RequestInterval   time.Duration
	Adaptive          bool
	ProgressiveStress bool
	Timeout           time.Duration
}

type AnalyzerConfig struct {
	TimeoutThreshold   time.Duration
	MaxResponseBodySize int64
	InfoLeakPatterns   []string
	CustomPatterns     []CustomPattern
}

type CustomPattern struct {
	Name        string
	Pattern     string
	Severity    Severity
	Description string
}

type FuzzConfig struct {
	Seed              int64
	MaxTestCases      int
	MaxDepth          int
	GenerateBoundary  bool
	GenerateMalicious bool
	Stateful          bool
	ExcludeEndpoints  []string
	ExcludeParams     []string
	CustomPayloads    map[string][]interface{}
}

type ReporterConfig struct {
	OutputFormats []string
	OutputDir     string
	Terminal      bool
	JSON          bool
	HTML          bool
	SARIF         bool
	FailOn        Severity
	BaselineFile  string
}

type FuzzStrategyType string

const (
	FuzzStrategySQLi       FuzzStrategyType = "sql_injection"
	FuzzStrategyXSS        FuzzStrategyType = "xss"
	FuzzStrategyPathTraversal FuzzStrategyType = "path_traversal"
	FuzzStrategyBoundary   FuzzStrategyType = "boundary"
	FuzzStrategyTypeConfusion FuzzStrategyType = "type_confusion"
	FuzzStrategyFormatString FuzzStrategyType = "format_string"
	FuzzStrategyDeepNested FuzzStrategyType = "deep_nested"
	FuzzStrategyAuthBypass FuzzStrategyType = "auth_bypass"
	FuzzStrategyIDOR       FuzzStrategyType = "idor"
	FuzzStrategyRateLimit  FuzzStrategyType = "rate_limit_bypass"
)

type SchedulerState struct {
	Queues            map[string][]*ScheduledOperation
	CurrentEndpoint   string
	CurrentStrategy   FuzzStrategyType
	ConsecutiveIssues map[string]int
	ConsecutiveClean  map[string]int
	UsedStrategies    map[string]map[FuzzStrategyType]bool
	ResourceEndpoints map[string][]string
	IsPaused          bool
	CurrentQPS        int
	BaseQPS           int
}

type ScheduledOperation struct {
	Operation    *Operation
	Priority     int
	ResourceType string
	Strategies   []FuzzStrategyType
}

type CoverageSnapshot struct {
	EndpointsTested    map[string]bool
	EndpointsTotal     int
	ParamsTested       map[string]map[string]map[string]bool
	ResponseCodes      map[string]map[int]bool
	EndpointCoverage   float64
	ParamCoverage      float64
	ResponseCoverage   float64
}

type ProgressEstimate struct {
	Completed        int
	Total            int
	PercentComplete  float64
	AvgTimePerTest   time.Duration
	RemainingTests   int
	EstimatedTimeLeft time.Duration
	ETA              time.Time
	CurrentQPS       float64
	WillExceedTimeout bool
}

type CheckpointData struct {
	Version            string
	Timestamp          time.Time
	CompletedTestIDs   []string
	CoverageSnapshot   *CoverageSnapshot
	Issues             []*Issue
	SchedulerState     *SchedulerState
	RandState          int64
	OpenAPISpecHash    string
	TargetURL          string
	ConfigSnapshot     *Config
}

const CheckpointVersion = "1.0"

type TUIState struct {
	IsRunning         bool
	IsPaused          bool
	CurrentQPS        float64
	CompletedTests    int
	TotalTests        int
	Runtime           time.Duration
	IssueCount        int
	RecentIssues      []*Issue
	Coverage          *Coverage
	CurrentEndpoint   string
	CurrentStrategy   FuzzStrategyType
	FocusedPanel      int
	Progress          *ProgressEstimate
	TimeoutWarning    string
	InitMessages      []string
}

type AuditFinding struct {
	ID             string
	RuleID         string
	RuleCategory   string
	Severity       Severity
	Title          string
	Description    string
	Endpoint       string
	Method         string
	FixSuggestion  string
	Evidence       map[string]interface{}
	Requests       []*HTTPRequest
	Responses      []*HTTPResponse
	Fingerprint    string
	IsStatic       bool
	CreatedAt      time.Time
}

type AuditRule struct {
	ID          string
	Category    string
	Severity    Severity
	Title       string
	Description string
	Enabled     bool
	FixSuggestion string
}

type AuditPolicy struct {
	EnabledRules       map[string]bool
	DisabledRules      map[string]bool
	CustomSeverities   map[string]Severity
	CustomSensitiveFields []string
	ExcludedPaths      []string
	CustomRules        []*CustomAuditRule
}

type CustomAuditRule struct {
	ID              string
	Category        string
	Severity        Severity
	Title           string
	Description     string
	JSONPath        string
	Condition       map[string]interface{}
	FixSuggestion   string
}

type AuditStats struct {
	TotalRules        int
	PassedRules       int
	FailedRules       int
	BySeverity        map[Severity]int
	ByCategory        map[string]int
	ComplianceScore   float64
}

type AuditReport struct {
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	APITitle        string
	TargetURL       string
	PolicyFile      string
	Findings        []*AuditFinding
	Stats           *AuditStats
	Config          *AuditConfig
	Policy          *AuditPolicy
	BaselineDiff    *AuditBaselineDiff
	ComplianceScore float64
}

type AuditBaselineDiff struct {
	NewFindings     []*AuditFinding
	FixedFindings   []*AuditFinding
	ExistingFindings []*AuditFinding
}

type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
	From  string      `json:"from,omitempty"`
}

type FixPatch struct {
	ID             string          `json:"id"`
	RuleID         string          `json:"rule_id"`
	RuleTitle      string          `json:"rule_title"`
	Description    string          `json:"description"`
	Severity       Severity        `json:"severity"`
	Endpoints      []string        `json:"endpoints"`
	Operations     []PatchOperation `json:"operations"`
	GeneratedAt    time.Time       `json:"generated_at"`
	HasConflict    bool            `json:"has_conflict"`
	ConflictReason string          `json:"conflict_reason,omitempty"`
	Dependencies   []string        `json:"dependencies,omitempty"`
	Priority       int             `json:"priority"`
}

type PatchValidationResult struct {
	IsValid  bool     `json:"is_valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type PatchPolicy struct {
	DefaultMaxLength int64                         `yaml:"default_max_length" json:"default_max_length"`
	NumericRanges    map[string]*NumericRangeConfig `yaml:"numeric_ranges" json:"numeric_ranges"`
	ErrorResponseSchema *ErrorResponseSchemaConfig  `yaml:"error_response_schema" json:"error_response_schema"`
}

type NumericRangeConfig struct {
	Minimum float64 `yaml:"minimum" json:"minimum"`
	Maximum float64 `yaml:"maximum" json:"maximum"`
}

type ErrorResponseSchemaConfig struct {
	ErrorCodeField string `yaml:"error_code_field" json:"error_code_field"`
	ErrorCodeType  string `yaml:"error_code_type" json:"error_code_type"`
	MessageField   string `yaml:"message_field" json:"message_field"`
	MessageType    string `yaml:"message_type" json:"message_type"`
}

type AuditConfig struct {
	SpecPath            string
	PolicyPath          string
	SeverityThreshold   Severity
	OutputDir           string
	OutputFormats       []string
	EnableDynamic       bool
	TargetURL           string
	Categories          []string
	BaselineFile        string
	Auth                AuthConfig
	RateLimit           RateLimitConfig
	Terminal            bool
	JSON                bool
	HTML                bool
	Fix                 bool
	FixAll              bool
	FixRules            string
	ExportPatches       bool
	ExportPatchesFormat string
	PatchPolicy         *PatchPolicy
}

type Config struct {
	OpenAPISpec string
	TargetURL   string
	Auth        AuthConfig
	RateLimit   RateLimitConfig
	Analyzer    AnalyzerConfig
	Fuzz        FuzzConfig
	Reporter    ReporterConfig
	Audit       AuditConfig
	UserConfig  string
	Timeout     time.Duration
	MaxConsecutiveTimeouts int
	Interactive bool
	ResumeFile  string
}
