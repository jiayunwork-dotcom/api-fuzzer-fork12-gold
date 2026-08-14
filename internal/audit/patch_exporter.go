package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"gopkg.in/yaml.v3"
)

type PatchExporter struct {
	config *core.AuditConfig
}

func NewPatchExporter(config *core.AuditConfig) *PatchExporter {
	return &PatchExporter{config: config}
}

type PatchFile struct {
	Metadata PatchFileMetadata `json:"metadata" yaml:"metadata"`
	Patch    interface{}       `json:"patch" yaml:"patch"`
}

type PatchFileMetadata struct {
	RuleID       string   `json:"rule_id" yaml:"rule_id"`
	RuleTitle    string   `json:"rule_title" yaml:"rule_title"`
	Description  string   `json:"description" yaml:"description"`
	Severity     string   `json:"severity" yaml:"severity"`
	Endpoints    []string `json:"endpoints" yaml:"endpoints"`
	GeneratedAt  string   `json:"generated_at" yaml:"generated_at"`
	HasConflict  bool     `json:"has_conflict" yaml:"has_conflict"`
	Dependencies []string `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
}

func (pe *PatchExporter) ExportPatches(patches []*core.FixPatch, outputDir string) error {
	patchesDir := filepath.Join(outputDir, "patches")
	if err := os.MkdirAll(patchesDir, 0755); err != nil {
		return fmt.Errorf("failed to create patches directory: %w", err)
	}

	format := pe.config.ExportPatchesFormat
	if format == "" {
		format = "jsonpatch"
	}

	exported := 0
	conflicts := 0
	for _, patch := range patches {
		if patch.HasConflict {
			conflicts++
		}

		switch format {
		case "jsonpatch":
			if err := pe.exportJSONPatch(patch, patchesDir); err != nil {
				return fmt.Errorf("failed to export patch %s: %w", patch.RuleID, err)
			}
		case "mergepatch":
			if err := pe.exportMergePatch(patch, patchesDir); err != nil {
				return fmt.Errorf("failed to export merge patch %s: %w", patch.RuleID, err)
			}
		case "yaml-diff":
			if err := pe.exportYAMLDiff(patch, patchesDir); err != nil {
				return fmt.Errorf("failed to export YAML diff %s: %w", patch.RuleID, err)
			}
		default:
			return fmt.Errorf("unsupported export format: %s (supported: jsonpatch, mergepatch, yaml-diff)", format)
		}
		exported++
	}

	fmt.Printf("\n📁 Exported %d patch(es) to: %s (format: %s)\n", exported, patchesDir, format)
	if conflicts > 0 {
		fmt.Printf("⚠️  %d patch(es) have conflicts and need manual review\n", conflicts)
	}

	return nil
}

func (pe *PatchExporter) exportJSONPatch(patch *core.FixPatch, dir string) error {
	patchFile := PatchFile{
		Metadata: PatchFileMetadata{
			RuleID:       patch.RuleID,
			RuleTitle:    patch.RuleTitle,
			Description:  patch.Description,
			Severity:     string(patch.Severity),
			Endpoints:    patch.Endpoints,
			GeneratedAt:  patch.GeneratedAt.Format(time.RFC3339),
			HasConflict:  patch.HasConflict,
			Dependencies: patch.Dependencies,
		},
		Patch: patch.Operations,
	}

	data, err := json.MarshalIndent(patchFile, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", sanitizeFilename(patch.RuleID))
	filePath := filepath.Join(dir, filename)
	return os.WriteFile(filePath, data, 0644)
}

func (pe *PatchExporter) exportMergePatch(patch *core.FixPatch, dir string) error {
	mergePatch := pe.buildMergePatch(patch)

	patchFile := PatchFile{
		Metadata: PatchFileMetadata{
			RuleID:       patch.RuleID,
			RuleTitle:    patch.RuleTitle,
			Description:  patch.Description,
			Severity:     string(patch.Severity),
			Endpoints:    patch.Endpoints,
			GeneratedAt:  patch.GeneratedAt.Format(time.RFC3339),
			HasConflict:  patch.HasConflict,
			Dependencies: patch.Dependencies,
		},
		Patch: mergePatch,
	}

	data, err := json.MarshalIndent(patchFile, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.merge.json", sanitizeFilename(patch.RuleID))
	filePath := filepath.Join(dir, filename)
	return os.WriteFile(filePath, data, 0644)
}

func (pe *PatchExporter) exportYAMLDiff(patch *core.FixPatch, dir string) error {
	type YAMLDiffFile struct {
		Metadata PatchFileMetadata `yaml:"metadata"`
		Changes  []YAMLDiffChange  `yaml:"changes"`
	}

	changes := make([]YAMLDiffChange, 0, len(patch.Operations))
	for _, op := range patch.Operations {
		change := YAMLDiffChange{
			Operation: op.Op,
			Path:      unescapeJSONPointerHuman(op.Path),
		}
		if op.From != "" {
			change.From = unescapeJSONPointerHuman(op.From)
		}
		if op.Value != nil {
			change.Value = op.Value
		}
		changes = append(changes, change)
	}

	diffFile := YAMLDiffFile{
		Metadata: PatchFileMetadata{
			RuleID:       patch.RuleID,
			RuleTitle:    patch.RuleTitle,
			Description:  patch.Description,
			Severity:     string(patch.Severity),
			Endpoints:    patch.Endpoints,
			GeneratedAt:  patch.GeneratedAt.Format(time.RFC3339),
			HasConflict:  patch.HasConflict,
			Dependencies: patch.Dependencies,
		},
		Changes: changes,
	}

	data, err := yaml.Marshal(diffFile)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.diff.yaml", sanitizeFilename(patch.RuleID))
	filePath := filepath.Join(dir, filename)
	return os.WriteFile(filePath, data, 0644)
}

type YAMLDiffChange struct {
	Operation string      `yaml:"operation"`
	Path      string      `yaml:"path"`
	From      string      `yaml:"from,omitempty"`
	Value     interface{} `yaml:"value,omitempty"`
}

func (pe *PatchExporter) buildMergePatch(patch *core.FixPatch) map[string]interface{} {
	result := make(map[string]interface{})

	for _, op := range patch.Operations {
		pe.applyOperationToMergePatch(result, op)
	}

	return result
}

func (pe *PatchExporter) applyOperationToMergePatch(result map[string]interface{}, op core.PatchOperation) {
	segments := parseJSONPointer(op.Path)
	if len(segments) == 0 {
		return
	}

	current := interface{}(result)
	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		switch c := current.(type) {
		case map[string]interface{}:
			if next, ok := c[seg]; ok {
				current = next
			} else {
				newMap := make(map[string]interface{})
				c[seg] = newMap
				current = newMap
			}
		}
	}

	lastSeg := segments[len(segments)-1]
	if m, ok := current.(map[string]interface{}); ok {
		switch op.Op {
		case "add", "replace":
			m[lastSeg] = op.Value
		case "remove":
			m[lastSeg] = nil
		}
	}
}

func sanitizeFilename(name string) string {
	s := strings.ReplaceAll(name, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return strings.ToLower(s)
}
