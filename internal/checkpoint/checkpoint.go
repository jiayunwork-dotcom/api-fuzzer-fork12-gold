package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

const defaultCheckpointFile = ".apifuzzer-checkpoint.json"

type Manager struct {
	checkpointFile string
	lastSaveTime   time.Time
	saveInterval   time.Duration
}

func NewManager(checkpointFile string) *Manager {
	if checkpointFile == "" {
		checkpointFile = defaultCheckpointFile
	}
	return &Manager{
		checkpointFile: checkpointFile,
		saveInterval:   30 * time.Second,
	}
}

func (m *Manager) ShouldSave() bool {
	return time.Since(m.lastSaveTime) >= m.saveInterval
}

func (m *Manager) Save(data *core.CheckpointData) error {
	data.Version = core.CheckpointVersion
	data.Timestamp = time.Now()

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	if err := os.WriteFile(m.checkpointFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint file: %w", err)
	}

	m.lastSaveTime = time.Now()
	return nil
}

func (m *Manager) Load() (*core.CheckpointData, error) {
	if _, err := os.Stat(m.checkpointFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("checkpoint file not found: %s", m.checkpointFile)
	}

	jsonData, err := os.ReadFile(m.checkpointFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	var data core.CheckpointData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	if data.Version != core.CheckpointVersion {
		return nil, fmt.Errorf("checkpoint version mismatch: expected %s, got %s", core.CheckpointVersion, data.Version)
	}

	return &data, nil
}

func (m *Manager) Delete() error {
	if _, err := os.Stat(m.checkpointFile); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(m.checkpointFile)
}

func (m *Manager) GetFilePath() string {
	return m.checkpointFile
}

func ComputeFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func CreateSnapshot(
	completedTestIDs []string,
	coverage *core.Coverage,
	issues []*core.Issue,
	schedulerState *core.SchedulerState,
	randState int64,
	openAPISpecHash string,
	targetURL string,
	config *core.Config,
) *core.CheckpointData {
	coverageSnapshot := &core.CoverageSnapshot{
		EndpointsTested:  make(map[string]bool),
		EndpointsTotal:   coverage.EndpointsTotal,
		ParamsTested:     make(map[string]map[string]map[string]bool),
		ResponseCodes:    make(map[string]map[int]bool),
		EndpointCoverage: coverage.EndpointCoverage(),
	}

	for k, v := range coverage.EndpointsTested {
		coverageSnapshot.EndpointsTested[k] = v
	}

	totalParams := 0
	testedParams := 0
	for path, params := range coverage.ParamsTested {
		coverageSnapshot.ParamsTested[path] = make(map[string]map[string]bool)
		for param, variants := range params {
			coverageSnapshot.ParamsTested[path][param] = make(map[string]bool)
			for variant, tested := range variants {
				coverageSnapshot.ParamsTested[path][param][variant] = tested
				totalParams++
				if tested {
					testedParams++
				}
			}
		}
	}
	if totalParams > 0 {
		coverageSnapshot.ParamCoverage = float64(testedParams) / float64(totalParams) * 100
	}

	totalCodes := 0
	testedCodes := 0
	for path, codes := range coverage.ResponseCodes {
		coverageSnapshot.ResponseCodes[path] = make(map[int]bool)
		for code, tested := range codes {
			coverageSnapshot.ResponseCodes[path][code] = tested
			totalCodes++
			if tested {
				testedCodes++
			}
		}
	}
	if totalCodes > 0 {
		coverageSnapshot.ResponseCoverage = float64(testedCodes) / float64(totalCodes) * 100
	}

	return &core.CheckpointData{
		CompletedTestIDs: append([]string{}, completedTestIDs...),
		CoverageSnapshot: coverageSnapshot,
		Issues:           append([]*core.Issue{}, issues...),
		SchedulerState:   schedulerState,
		RandState:        randState,
		OpenAPISpecHash:  openAPISpecHash,
		TargetURL:        targetURL,
		ConfigSnapshot:   config,
	}
}

type CompatibilityResult struct {
	IsCompatible    bool
	HasChanges      bool
	AddedEndpoints  []string
	RemovedEndpoints []string
	Messages        []string
}

func CheckCompatibility(checkpoint *core.CheckpointData, currentAPI *core.API, currentTargetURL string) CompatibilityResult {
	result := CompatibilityResult{
		IsCompatible: true,
	}

	if checkpoint.TargetURL != currentTargetURL {
		result.IsCompatible = false
		result.Messages = append(result.Messages,
			fmt.Sprintf("Target URL mismatch: checkpoint=%s, current=%s", checkpoint.TargetURL, currentTargetURL))
	}

	checkpointEndpoints := make(map[string]bool)
	currentEndpoints := make(map[string]bool)

	if checkpoint.CoverageSnapshot != nil {
		for ep := range checkpoint.CoverageSnapshot.EndpointsTested {
			checkpointEndpoints[ep] = true
		}
	}

	for path, methods := range currentAPI.Paths {
		for method := range methods {
			key := method + " " + path
			currentEndpoints[key] = true
			if !checkpointEndpoints[key] {
				result.AddedEndpoints = append(result.AddedEndpoints, key)
				result.HasChanges = true
			}
		}
	}

	for ep := range checkpointEndpoints {
		if !currentEndpoints[ep] && checkpoint.CoverageSnapshot.EndpointsTested[ep] {
			result.RemovedEndpoints = append(result.RemovedEndpoints, ep)
			result.HasChanges = true
		}
	}

	if len(result.AddedEndpoints) > 0 {
		result.Messages = append(result.Messages,
			fmt.Sprintf("Found %d new endpoints that will be added to the scan queue", len(result.AddedEndpoints)))
	}

	if len(result.RemovedEndpoints) > 0 {
		result.Messages = append(result.Messages,
			fmt.Sprintf("Found %d removed endpoints; their results will be preserved but not retested", len(result.RemovedEndpoints)))
	}

	return result
}

func ExportIssuesSnapshot(issues []*core.Issue, outputPath string) error {
	data := map[string]interface{}{
		"export_time": time.Now().Format(time.RFC3339),
		"issue_count": len(issues),
		"issues":      issues,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}
