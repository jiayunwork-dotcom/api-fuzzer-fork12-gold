package core

import "testing"

func TestTruncateString_ExactLengthKept(t *testing.T) {
	got := TruncateString("hello", 5)
	if got != "hello" {
		t.Fatalf("TruncateString(%q, 5)=%q, want hello", "hello", got)
	}
}
