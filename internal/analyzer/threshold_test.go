package analyzer

import (
	"testing"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

func TestCheckSeverityThreshold_EqualCounts(t *testing.T) {
	if !CheckSeverityThreshold(core.SeverityHigh, core.SeverityHigh) {
		t.Fatal("equal severity should meet the threshold")
	}
}
