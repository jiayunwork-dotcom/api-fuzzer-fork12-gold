package audit

import (
	"testing"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

func TestIsPathExcluded_Prefix(t *testing.T) {
	p := &core.AuditPolicy{ExcludedPaths: []string{"/health"}}
	if !IsPathExcluded("/health/live", p) {
		t.Fatal("/health/live should be excluded by prefix /health")
	}
}
