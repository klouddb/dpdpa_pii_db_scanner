package piiscanner

import (
	"context"
	"testing"
)

func TestPiiScannerDetect(t *testing.T) {
	runner := NewPiiScanner().
		AddValueDetector(NewRegexValueDetector()).
		AddColumnDetector(NewRegexColumnDetector())
	if err := runner.Init(); err != nil {
		t.Fatalf("initialize scanner: %v", err)
	}

	tests := []struct {
		name   string
		column string
		value  string
		want   PIILabel
	}{
		{
			name:   "matching email column and value",
			column: "email_address",
			value:  "alice@example.com",
			want:   PIILabel_Email,
		},
		{
			name:   "matching PAN column and value",
			column: "pan_number",
			value:  "ABCDE1234F",
			want:   PIILabel_PANNumber,
		},
		{
			name:   "column label is fallback when value is not detected",
			column: "email_address",
			value:  "not-an-email",
			want:   PIILabel_Email,
		},
		{
			name:   "value without matching column is ignored",
			column: "description",
			value:  "alice@example.com",
			want:   "",
		},
		{
			name:   "empty value is ignored",
			column: "email_address",
			value:  "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runner.Detect(context.Background(), tt.column, tt.value)
			if err != nil {
				t.Fatalf("detect column %q value %q: %v", tt.column, tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("detect column %q value %q: got %q, want %q", tt.column, tt.value, got, tt.want)
			}
		})
	}
}
