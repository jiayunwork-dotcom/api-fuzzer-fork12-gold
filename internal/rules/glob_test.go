package rules

import "testing"

func TestMatchGlob_StarPrefix(t *testing.T) {
	if !matchGlob("*.go", "main.go") {
		t.Fatal("*.go should match main.go")
	}
}
