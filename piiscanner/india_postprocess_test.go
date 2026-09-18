package piiscanner

import (
	"context"
	"testing"
)

func TestMergeIndiaValueWeight(t *testing.T) {
	tests := []struct {
		name         string
		label        string
		columnWeight float64
		valueWeight  float64
		want         float64
	}{
		{
			name:         "weight-merge entity with medium+ column",
			label:        string(PIILabel_PANNumber),
			columnWeight: 1.0,
			valueWeight:  0.3,
			want:         0.65,
		},
		{
			name:         "weight-merge entity with weak column",
			label:        string(PIILabel_PANNumber),
			columnWeight: 0.3,
			valueWeight:  0.5,
			want:         0.5,
		},
		{
			name:         "non weight-merge entity unchanged",
			label:        string(PIILabel_Email),
			columnWeight: 1.0,
			valueWeight:  0.3,
			want:         0.3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeIndiaValueWeight(tt.label, tt.columnWeight, tt.valueWeight)
			if got != tt.want {
				t.Fatalf("MergeIndiaValueWeight()=%v want %v", got, tt.want)
			}
		})
	}
}

func TestRunIndiaUnrecognizedColumnFallbacks_SkipsWhenColumnMatched(t *testing.T) {
	tests := []struct {
		name           string
		hasColumnMatch bool
		samples        []string
		wantLen        int
	}{
		{
			name:           "column matched skips fallback",
			hasColumnMatch: true,
			samples:        []string{"ABCDE1234F"},
			wantLen:        0,
		},
		{
			name:           "empty samples",
			hasColumnMatch: false,
			samples:        nil,
			wantLen:        0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RunIndiaUnrecognizedColumnFallbacks(context.Background(), tt.samples, tt.hasColumnMatch, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("len=%d want %d (%v)", len(got), tt.wantLen, got)
			}
		})
	}
}
