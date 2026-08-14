package audit

import "testing"

func TestParseInt_DecimalTen(t *testing.T) {
	got, err := parseInt("10")
	if err != nil {
		t.Fatalf("parseInt: %v", err)
	}
	if got != 10 {
		t.Fatalf("parseInt(10)=%d, want 10", got)
	}
}
