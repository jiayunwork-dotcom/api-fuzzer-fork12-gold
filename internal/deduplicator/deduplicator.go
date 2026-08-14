package deduplicator

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type Deduplicator struct {
	mu           sync.RWMutex
	issues       map[string]*core.Issue
	falsePositives map[string]bool
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		issues:       make(map[string]*core.Issue),
		falsePositives: make(map[string]bool),
	}
}

func (d *Deduplicator) Add(issues []*core.Issue) []*core.Issue {
	d.mu.Lock()
	defer d.mu.Unlock()

	var newIssues []*core.Issue

	for _, issue := range issues {
		issue.ComputeFingerprint()

		if d.falsePositives[issue.Fingerprint] {
			continue
		}

		if existing, ok := d.issues[issue.Fingerprint]; ok {
			existing.Requests = append(existing.Requests, issue.Requests...)
			existing.Responses = append(existing.Responses, issue.Responses...)
			existing.TestCaseIDs = append(existing.TestCaseIDs, issue.TestCaseIDs...)
			existing.Inputs = append(existing.Inputs, issue.Inputs...)
		} else {
			d.issues[issue.Fingerprint] = issue
			newIssues = append(newIssues, issue)
		}
	}

	return newIssues
}

func (d *Deduplicator) GetIssues() []*core.Issue {
	d.mu.RLock()
	defer d.mu.RUnlock()

	issues := make([]*core.Issue, 0, len(d.issues))
	for _, issue := range d.issues {
		if !d.falsePositives[issue.Fingerprint] {
			issues = append(issues, issue)
		}
	}
	return issues
}

func (d *Deduplicator) MarkFalsePositive(fingerprint string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.falsePositives[fingerprint] = true
}

func (d *Deduplicator) IsFalsePositive(fingerprint string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.falsePositives[fingerprint]
}

func (d *Deduplicator) LoadFalsePositives(path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var fps []string
	if err := json.Unmarshal(data, &fps); err != nil {
		return err
	}

	for _, fp := range fps {
		d.falsePositives[fp] = true
	}
	return nil
}

func (d *Deduplicator) SaveFalsePositives(path string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	fps := make([]string, 0, len(d.falsePositives))
	for fp := range d.falsePositives {
		fps = append(fps, fp)
	}

	data, err := json.MarshalIndent(fps, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (d *Deduplicator) LoadBaseline(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var baseline struct {
		Issues []*core.Issue `json:"issues"`
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		return err
	}

	for _, issue := range baseline.Issues {
		issue.ComputeFingerprint()
		d.falsePositives[issue.Fingerprint] = true
	}

	return nil
}

func (d *Deduplicator) Stats() map[string]int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	totalIssues := 0
	for _, issue := range d.issues {
		if !d.falsePositives[issue.Fingerprint] {
			totalIssues++
		}
	}

	return map[string]int{
		"total_issues":     len(d.issues),
		"unique_issues":    totalIssues,
		"false_positives":  len(d.falsePositives),
	}
}

func MergeIssues(issues []*core.Issue) []*core.Issue {
	d := NewDeduplicator()
	d.Add(issues)
	return d.GetIssues()
}
