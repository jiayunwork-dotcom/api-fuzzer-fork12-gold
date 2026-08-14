package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"github.com/api-fuzzer/apifuzzer/internal/openapi"
	"gopkg.in/yaml.v3"
)

type PatchApplier struct {
	config  *core.AuditConfig
	rawSpec map[string]interface{}
}

func NewPatchApplier(config *core.AuditConfig, rawSpec map[string]interface{}) *PatchApplier {
	return &PatchApplier{
		config:  config,
		rawSpec: rawSpec,
	}
}

func LoadRawSpec(specPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	var raw map[string]interface{}
	ext := strings.ToLower(filepath.Ext(specPath))
	if ext == ".json" {
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("failed to parse JSON spec: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("failed to parse YAML spec: %w", err)
		}
	}
	return raw, nil
}

func (pa *PatchApplier) ValidatePatch(patch *core.FixPatch) *core.PatchValidationResult {
	result := &core.PatchValidationResult{
		IsValid:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	for _, op := range patch.Operations {
		switch op.Op {
		case "add":
			parentPath, _ := splitLastSegment(op.Path)
			if parentPath != "" && parentPath != "/" {
				parent := navigateJSONPointer(pa.rawSpec, parentPath)
				if parent == nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("Parent path %s will be created for add operation", parentPath))
				}
			}
		case "remove":
			target := navigateJSONPointer(pa.rawSpec, op.Path)
			if target == nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Target path %s does not exist for remove operation", op.Path))
				result.IsValid = false
			}
		case "replace":
			target := navigateJSONPointer(pa.rawSpec, op.Path)
			if target == nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Target path %s does not exist for replace operation", op.Path))
				result.IsValid = false
			}
		case "move":
			src := navigateJSONPointer(pa.rawSpec, op.From)
			if src == nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Source path %s does not exist for move operation", op.From))
				result.IsValid = false
			}
			parentPath, _ := splitLastSegment(op.Path)
			if parentPath != "" && parentPath != "/" {
				parent := navigateJSONPointer(pa.rawSpec, parentPath)
				if parent == nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Destination parent path %s does not exist for move operation", parentPath))
					result.IsValid = false
				}
			}
		default:
			result.Warnings = append(result.Warnings, fmt.Sprintf("Unknown operation type: %s", op.Op))
		}
	}

	if result.IsValid {
		testSpec := pa.deepCopyMap(pa.rawSpec)
		for _, op := range patch.Operations {
			if err := applyOperation(testSpec, op); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Patch application test failed: %v", err))
				result.IsValid = false
				break
			}
		}

		if result.IsValid {
			if err := validateOpenAPIFormat(testSpec); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Resulting spec may not be valid OpenAPI: %v", err))
			}
		}
	}

	return result
}

func (pa *PatchApplier) ValidatePatches(patches []*core.FixPatch) map[string]*core.PatchValidationResult {
	results := make(map[string]*core.PatchValidationResult)
	for _, p := range patches {
		results[p.ID] = pa.ValidatePatch(p)
	}
	return results
}

func (pa *PatchApplier) ApplyPatches(patches []*core.FixPatch) (map[string]interface{}, []error) {
	ordered := ResolvePatchOrder(patches)
	spec := pa.deepCopyMap(pa.rawSpec)
	errs := make([]error, 0)

	for i, patch := range ordered {
		if patch.HasConflict {
			errs = append(errs, fmt.Errorf("skipping patch %s [%s]: has conflict - %s", patch.ID, patch.RuleID, patch.ConflictReason))
			continue
		}

		validation := pa.ValidatePatch(patch)
		if !validation.IsValid {
			errs = append(errs, fmt.Errorf("skipping patch %s [%s]: validation failed - %s", patch.ID, patch.RuleID, strings.Join(validation.Errors, "; ")))
			continue
		}

		for _, op := range patch.Operations {
			if op.Op == "move" {
				updateRemainingPatchPaths(ordered[i+1:], op.From, op.Path)
			}
			if err := applyOperation(spec, op); err != nil {
				errs = append(errs, fmt.Errorf("failed to apply patch %s [%s]: %v", patch.ID, patch.RuleID, err))
				break
			}
		}
	}

	return spec, errs
}

func updateRemainingPatchPaths(patches []*core.FixPatch, fromPath, toPath string) {
	for _, patch := range patches {
		for j, op := range patch.Operations {
			if strings.HasPrefix(op.Path, fromPath+"/") {
				patch.Operations[j].Path = toPath + op.Path[len(fromPath):]
			}
			if op.From != "" && strings.HasPrefix(op.From, fromPath+"/") {
				patch.Operations[j].From = toPath + op.From[len(fromPath):]
			}
		}
	}
}

func (pa *PatchApplier) WriteFixedSpec(spec map[string]interface{}, specPath string) error {
	dir := filepath.Dir(specPath)
	base := filepath.Base(specPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	fixedPath := filepath.Join(dir, name+".fixed"+ext)

	data, err := yaml.Marshal(spec)
	if err != nil {
		return fmt.Errorf("failed to marshal fixed spec: %w", err)
	}

	if err := os.WriteFile(fixedPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write fixed spec: %w", err)
	}

	fmt.Printf("✅ Fixed spec written to: %s\n", fixedPath)
	return nil
}

func (pa *PatchApplier) PreviewDiff(patches []*core.FixPatch) {
	fmt.Println()
	fmt.Println(auditColorBold + auditColorCyan + "╔════════════════════════════════════════════════════════════╗" + auditColorReset)
	fmt.Println(auditColorBold + auditColorCyan + "║              Available Fix Patches                         ║" + auditColorReset)
	fmt.Println(auditColorBold + auditColorCyan + "╚════════════════════════════════════════════════════════════╝" + auditColorReset)
	fmt.Println()

	total := len(patches)
	applicable := 0
	conflicting := 0
	for _, p := range patches {
		if p.HasConflict {
			conflicting++
		} else {
			applicable++
		}
	}
	fmt.Printf("Total patches: %d | Applicable: %s%d"+auditColorReset+" | Conflicting: %s%d"+auditColorReset+"\n",
		total, auditColorGreen, applicable, auditColorRed, conflicting)
	fmt.Println(strings.Repeat("─", 80))

	for i, patch := range patches {
		statusIcon := "✅"
		statusText := "applicable"
		if patch.HasConflict {
			statusIcon = "⚠️ "
			statusText = "needs manual resolution"
		}

		severityColor := getSeverityColor(patch.Severity)
		fmt.Println()
		fmt.Printf("%s %s[%s] %s%s %s[%s]%s\n", statusIcon,
			severityColor+auditColorBold, patch.RuleID, auditColorReset,
			patch.RuleTitle,
			severityColor, patch.Severity, auditColorReset)
		fmt.Printf("   Status: %s\n", statusText)
		fmt.Printf("   Description: %s\n", patch.Description)
		if len(patch.Endpoints) > 0 {
			fmt.Printf("   Endpoints: %s\n", strings.Join(patch.Endpoints, ", "))
		}
		if patch.HasConflict {
			fmt.Printf("   %sConflict: %s%s\n", auditColorRed, patch.ConflictReason, auditColorReset)
		}
		if len(patch.Dependencies) > 0 {
			fmt.Printf("   Dependencies: %s\n", strings.Join(patch.Dependencies, ", "))
		}

		fmt.Println()
		fmt.Printf("   %sPatch Operations (diff preview):%s\n", auditColorBold, auditColorReset)
		fmt.Println(strings.Repeat("─", 60))

		originalSpec := pa.deepCopyMap(pa.rawSpec)
		for _, op := range patch.Operations {
			pa.previewOperation(originalSpec, op)
		}

		if i < len(patches)-1 {
			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))
}

func (pa *PatchApplier) previewOperation(spec map[string]interface{}, op core.PatchOperation) {
	switch op.Op {
	case "add":
		pa.previewAdd(op)
	case "remove":
		pa.previewRemove(spec, op)
	case "replace":
		pa.previewReplace(spec, op)
	case "move":
		pa.previewMove(op)
	}
}

func (pa *PatchApplier) previewAdd(op core.PatchOperation) {
	humanPath := unescapeJSONPointerHuman(op.Path)
	fmt.Printf("   %s+ %s%s\n", auditColorGreen, humanPath, auditColorReset)

	valueYAML, _ := yaml.Marshal(op.Value)
	lines := strings.Split(strings.TrimSpace(string(valueYAML)), "\n")
	for _, line := range lines {
		fmt.Printf("   %s+   %s%s\n", auditColorGreen, line, auditColorReset)
	}
}

func (pa *PatchApplier) previewRemove(spec map[string]interface{}, op core.PatchOperation) {
	humanPath := unescapeJSONPointerHuman(op.Path)
	existing := navigateJSONPointer(spec, op.Path)
	fmt.Printf("   %s- %s%s\n", auditColorRed, humanPath, auditColorReset)
	if existing != nil {
		valueYAML, _ := yaml.Marshal(existing)
		lines := strings.Split(strings.TrimSpace(string(valueYAML)), "\n")
		for _, line := range lines {
			fmt.Printf("   %s-   %s%s\n", auditColorRed, line, auditColorReset)
		}
	}
}

func (pa *PatchApplier) previewReplace(spec map[string]interface{}, op core.PatchOperation) {
	humanPath := unescapeJSONPointerHuman(op.Path)
	existing := navigateJSONPointer(spec, op.Path)
	if existing != nil {
		valueYAML, _ := yaml.Marshal(existing)
		lines := strings.Split(strings.TrimSpace(string(valueYAML)), "\n")
		for _, line := range lines {
			fmt.Printf("   %s-   %s%s\n", auditColorRed, line, auditColorReset)
		}
	}
	valueYAML, _ := yaml.Marshal(op.Value)
	lines := strings.Split(strings.TrimSpace(string(valueYAML)), "\n")
	for _, line := range lines {
		fmt.Printf("   %s+   %s%s\n", auditColorGreen, line, auditColorReset)
	}
	_ = humanPath
}

func (pa *PatchApplier) previewMove(op core.PatchOperation) {
	fromPath := unescapeJSONPointerHuman(op.From)
	toPath := unescapeJSONPointerHuman(op.Path)
	fmt.Printf("   %s~ Move: %s -> %s%s\n", auditColorYellow, fromPath, toPath, auditColorReset)
}

func ReAuditFixedSpec(specPath string, config *core.AuditConfig, patches []*core.FixPatch) {
	fmt.Println()
	fmt.Println(auditColorBold + "🔄 Re-auditing fixed specification..." + auditColorReset)

	api, err := openapi.ParseOpenAPI(specPath)
	if err != nil {
		fmt.Printf("%s⚠️  Failed to parse fixed spec for re-audit: %v%s\n", auditColorRed, err, auditColorReset)
		return
	}

	policy, err := LoadPolicy(config.PolicyPath)
	if err != nil {
		fmt.Printf("%s⚠️  Failed to load policy for re-audit: %v%s\n", auditColorRed, err, auditColorReset)
		return
	}

	staticAnalyzer := NewStaticAnalyzer(api, policy, config)
	findings := staticAnalyzer.Analyze()

	appliedRuleIDs := make(map[string]bool)
	for _, p := range patches {
		if !p.HasConflict {
			appliedRuleIDs[p.RuleID] = true
		}
	}

	fixed := 0
	stillFailing := 0
	for _, f := range findings {
		if appliedRuleIDs[f.RuleID] {
			stillFailing++
		}
	}
	fixed = len(appliedRuleIDs) - stillFailing

	if fixed > 0 {
		fmt.Printf("%s✅ %d rule(s) verified as fixed after applying patches%s\n", auditColorGreen, fixed, auditColorReset)
	}
	if stillFailing > 0 {
		fmt.Printf("%s⚠️  %d rule(s) still have findings after patch application:%s\n", auditColorRed, stillFailing, auditColorReset)
		seen := make(map[string]bool)
		for _, f := range findings {
			if appliedRuleIDs[f.RuleID] && !seen[f.RuleID] {
				seen[f.RuleID] = true
				fmt.Printf("   - %s: %s (%s %s)\n", f.RuleID, f.Title, f.Method, f.Endpoint)
			}
		}
	}
}

func applyOperation(doc map[string]interface{}, op core.PatchOperation) error {
	switch op.Op {
	case "add":
		return applyAdd(doc, op.Path, op.Value)
	case "remove":
		return applyRemove(doc, op.Path)
	case "replace":
		return applyReplace(doc, op.Path, op.Value)
	case "move":
		return applyMove(doc, op.From, op.Path)
	default:
		return fmt.Errorf("unsupported operation: %s", op.Op)
	}
}

func applyAdd(doc map[string]interface{}, path string, value interface{}) error {
	segments := parseJSONPointer(path)
	if len(segments) == 0 {
		return fmt.Errorf("empty path for add operation")
	}

	current := interface{}(doc)
	for i := 0; i < len(segments)-1; i++ {
		next, err := navigateSegment(current, segments[i])
		if err != nil {
			if m, ok := current.(map[string]interface{}); ok {
				newMap := make(map[string]interface{})
				m[segments[i]] = newMap
				current = newMap
			} else {
				return fmt.Errorf("cannot create intermediate path at %s: %w", strings.Join(segments[:i+1], "/"), err)
			}
		} else {
			current = next
		}
	}

	lastSegment := segments[len(segments)-1]
	return setSegment(current, lastSegment, value)
}

func applyRemove(doc map[string]interface{}, path string) error {
	segments := parseJSONPointer(path)
	if len(segments) == 0 {
		return fmt.Errorf("empty path for remove operation")
	}

	current := interface{}(doc)
	for i := 0; i < len(segments)-1; i++ {
		next, err := navigateSegment(current, segments[i])
		if err != nil {
			return fmt.Errorf("cannot navigate to %s: %w", strings.Join(segments[:i+1], "/"), err)
		}
		current = next
	}

	lastSegment := segments[len(segments)-1]
	return deleteSegment(current, lastSegment)
}

func applyReplace(doc map[string]interface{}, path string, value interface{}) error {
	if err := applyRemove(doc, path); err != nil {
		return err
	}
	return applyAdd(doc, path, value)
}

func applyMove(doc map[string]interface{}, from, to string) error {
	value := navigateJSONPointer(doc, from)
	if value == nil {
		return fmt.Errorf("source path %s not found for move", from)
	}

	valueCopy := deepCopyValue(value)
	if err := applyRemove(doc, from); err != nil {
		return err
	}
	return applyAdd(doc, to, valueCopy)
}

func parseJSONPointer(pointer string) []string {
	if pointer == "" || pointer == "/" {
		return []string{}
	}
	parts := strings.Split(pointer, "/")
	result := make([]string, 0, len(parts)-1)
	for i, part := range parts {
		if i == 0 {
			continue
		}
		result = append(result, unescapeJSONPointer(part))
	}
	return result
}

func unescapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~1", "/")
	s = strings.ReplaceAll(s, "~0", "~")
	return s
}

func unescapeJSONPointerHuman(s string) string {
	parts := strings.Split(s, "/")
	for i, part := range parts {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")
		if strings.HasPrefix(part, "/") {
			part = part[1:]
		}
		parts[i] = part
	}
	return strings.Join(parts, "/")
}

func navigateJSONPointer(doc map[string]interface{}, pointer string) interface{} {
	segments := parseJSONPointer(pointer)
	var current interface{} = doc
	for _, seg := range segments {
		switch c := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = c[seg]
			if !ok {
				return nil
			}
		case []interface{}:
			idx := -1
			if seg == "-" {
				return nil
			}
			fmt.Sscanf(seg, "%d", &idx)
			if idx < 0 || idx >= len(c) {
				return nil
			}
			current = c[idx]
		default:
			return nil
		}
	}
	return current
}

func navigateSegment(current interface{}, segment string) (interface{}, error) {
	switch c := current.(type) {
	case map[string]interface{}:
		val, ok := c[segment]
		if !ok {
			return nil, fmt.Errorf("key %s not found", segment)
		}
		return val, nil
	case []interface{}:
		if segment == "-" {
			return nil, fmt.Errorf("cannot navigate to end of array")
		}
		var idx int
		if _, err := fmt.Sscanf(segment, "%d", &idx); err != nil {
			return nil, fmt.Errorf("invalid array index: %s", segment)
		}
		if idx < 0 || idx >= len(c) {
			return nil, fmt.Errorf("array index %d out of range (len=%d)", idx, len(c))
		}
		return c[idx], nil
	default:
		return nil, fmt.Errorf("cannot navigate through %T", current)
	}
}

func setSegment(current interface{}, segment string, value interface{}) error {
	switch c := current.(type) {
	case map[string]interface{}:
		c[segment] = value
		return nil
	case []interface{}:
		if segment == "-" {
			return fmt.Errorf("append to array not supported in this context")
		}
		var idx int
		if _, err := fmt.Sscanf(segment, "%d", &idx); err != nil {
			return fmt.Errorf("invalid array index: %s", segment)
		}
		if idx == len(c) {
			return fmt.Errorf("cannot extend array at index %d", idx)
		}
		if idx < 0 || idx > len(c) {
			return fmt.Errorf("array index %d out of range", idx)
		}
		c[idx] = value
		return nil
	default:
		return fmt.Errorf("cannot set value in %T", current)
	}
}

func deleteSegment(current interface{}, segment string) error {
	switch c := current.(type) {
	case map[string]interface{}:
		delete(c, segment)
		return nil
	case []interface{}:
		var idx int
		if _, err := fmt.Sscanf(segment, "%d", &idx); err != nil {
			return fmt.Errorf("invalid array index: %s", segment)
		}
		if idx < 0 || idx >= len(c) {
			return fmt.Errorf("array index %d out of range", idx)
		}
		return nil
	default:
		return fmt.Errorf("cannot delete from %T", current)
	}
}

func splitLastSegment(path string) (string, string) {
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		return "", path
	}
	return path[:lastSlash], path[lastSlash+1:]
}

func (pa *PatchApplier) deepCopyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = deepCopyValue(v)
	}
	return result
}

func deepCopyValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[k] = deepCopyValue(v)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = deepCopyValue(v)
		}
		return result
	case string, int, int64, float64, bool:
		return val
	default:
		b, _ := json.Marshal(v)
		var result interface{}
		json.Unmarshal(b, &result)
		return result
	}
}

func validateOpenAPIFormat(spec map[string]interface{}) error {
	if _, ok := spec["openapi"]; !ok {
		return fmt.Errorf("missing 'openapi' field")
	}
	if info, ok := spec["info"]; ok {
		if infoMap, ok := info.(map[string]interface{}); ok {
			if _, ok := infoMap["title"]; !ok {
				return fmt.Errorf("missing 'info.title' field")
			}
		}
	} else {
		return fmt.Errorf("missing 'info' field")
	}
	if _, ok := spec["paths"]; !ok {
		return fmt.Errorf("missing 'paths' field")
	}
	return nil
}

func getSeverityColor(sev core.Severity) string {
	switch sev {
	case core.SeverityCritical:
		return auditColorRed + auditColorBold
	case core.SeverityHigh:
		return auditColorRed
	case core.SeverityMedium:
		return auditColorYellow
	case core.SeverityLow:
		return auditColorBlue
	case core.SeverityInfo:
		return auditColorGreen
	default:
		return auditColorReset
	}
}

func GenerateFullDiffPreview(specPath string, originalSpec map[string]interface{}, fixedSpec map[string]interface{}) {
	originalYAML, _ := yaml.Marshal(originalSpec)
	fixedYAML, _ := yaml.Marshal(fixedSpec)

	originalLines := strings.Split(string(originalYAML), "\n")
	fixedLines := strings.Split(string(fixedYAML), "\n")

	fmt.Println()
	fmt.Println(auditColorBold + auditColorCyan + "Full Diff Preview:" + auditColorReset)
	fmt.Println(strings.Repeat("─", 80))

	maxLen := len(originalLines)
	if len(fixedLines) > maxLen {
		maxLen = len(fixedLines)
	}

	for i := 0; i < maxLen; i++ {
		var oLine, fLine string
		if i < len(originalLines) {
			oLine = originalLines[i]
		}
		if i < len(fixedLines) {
			fLine = fixedLines[i]
		}

		if i >= len(originalLines) {
			fmt.Printf("%s+ %s%s\n", auditColorGreen, fLine, auditColorReset)
		} else if i >= len(fixedLines) {
			fmt.Printf("%s- %s%s\n", auditColorRed, oLine, auditColorReset)
		} else if oLine != fLine {
			fmt.Printf("%s- %s%s\n", auditColorRed, oLine, auditColorReset)
			fmt.Printf("%s+ %s%s\n", auditColorGreen, fLine, auditColorReset)
		}
	}
}

func RunFixFlow(config *core.AuditConfig, patches []*core.FixPatch, specPath string) error {
	rawSpec, err := LoadRawSpec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec for patching: %w", err)
	}

	applier := NewPatchApplier(config, rawSpec)

	if config.Fix {
		applier.PreviewDiff(patches)
	}

	if config.FixAll {
		nonConflicting := GetNonConflictingPatches(patches)
		if len(nonConflicting) == 0 {
			fmt.Println("⚠️  No applicable patches (all have conflicts)")
			return nil
		}

		validation := applier.ValidatePatches(nonConflicting)
		validPatches := make([]*core.FixPatch, 0)
		for _, p := range nonConflicting {
			if v, ok := validation[p.ID]; ok && v.IsValid {
				validPatches = append(validPatches, p)
			} else if ok {
				fmt.Printf("⚠️  Skipping patch %s: %s\n", p.RuleID, strings.Join(v.Errors, "; "))
			}
		}

		if len(validPatches) == 0 {
			fmt.Println("⚠️  No valid patches to apply")
			return nil
		}

		fmt.Printf("\n🔧 Applying %d valid patches...\n", len(validPatches))
		fixedSpec, errs := applier.ApplyPatches(validPatches)
		for _, e := range errs {
			fmt.Printf("⚠️  %v\n", e)
		}

		if err := applier.WriteFixedSpec(fixedSpec, specPath); err != nil {
			return fmt.Errorf("failed to write fixed spec: %w", err)
		}

		fixedPath := buildFixedPath(specPath)
		ReAuditFixedSpec(fixedPath, config, validPatches)

		_ = fixedSpec
	}

	if config.FixRules != "" {
		ruleIDs := strings.Split(config.FixRules, ",")
		filtered := FilterPatchesByRules(patches, ruleIDs)
		nonConflicting := GetNonConflictingPatches(filtered)

		if len(nonConflicting) == 0 {
			fmt.Printf("⚠️  No applicable patches for rules: %s\n", config.FixRules)
			return nil
		}

		fmt.Printf("\n🔧 Applying %d patches for rules: %s\n", len(nonConflicting), config.FixRules)
		fixedSpec, errs := applier.ApplyPatches(nonConflicting)
		for _, e := range errs {
			fmt.Printf("⚠️  %v\n", e)
		}

		if err := applier.WriteFixedSpec(fixedSpec, specPath); err != nil {
			return fmt.Errorf("failed to write fixed spec: %w", err)
		}

		fixedPath := buildFixedPath(specPath)
		ReAuditFixedSpec(fixedPath, config, nonConflicting)

		_ = fixedSpec
	}

	return nil
}

func buildFixedPath(specPath string) string {
	dir := filepath.Dir(specPath)
	base := filepath.Base(specPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, name+".fixed"+ext)
}

func ShouldRunFix(config *core.AuditConfig) bool {
	return config.Fix || config.FixAll || config.FixRules != ""
}

func CountSpecChanges(original, fixed map[string]interface{}) int {
	o, _ := yaml.Marshal(original)
	f, _ := yaml.Marshal(fixed)
	oLines := strings.Split(string(o), "\n")
	fLines := strings.Split(string(f), "\n")

	changes := 0
	maxLen := len(oLines)
	if len(fLines) > maxLen {
		maxLen = len(fLines)
	}
	for i := 0; i < maxLen; i++ {
		var oLine, fLine string
		if i < len(oLines) {
			oLine = oLines[i]
		}
		if i < len(fLines) {
			fLine = fLines[i]
		}
		if oLine != fLine {
			changes++
		}
	}
	return changes
}
