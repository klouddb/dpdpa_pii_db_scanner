package piiscanner

import "testing"

func TestIsIndiaRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   bool
	}{
		{name: "exact", region: "india", want: true},
		{name: "upper", region: "INDIA", want: true},
		{name: "padded", region: "  India ", want: true},
		{name: "empty", region: "", want: false},
		{name: "us", region: "us", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIndiaRegion(tt.region); got != tt.want {
				t.Fatalf("IsIndiaRegion(%q)=%v want %v", tt.region, got, tt.want)
			}
		})
	}
}

func TestNormalizeRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{name: "india", region: "INDIA", want: RegionIndia},
		{name: "empty", region: "  ", want: ""},
		{name: "other", region: "us", want: "us"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeRegion(tt.region); got != tt.want {
				t.Fatalf("NormalizeRegion(%q)=%q want %q", tt.region, got, tt.want)
			}
		})
	}
}

func TestIsWeightMergeEntity(t *testing.T) {
	tests := []struct {
		name  string
		label PIILabel
		want  bool
	}{
		{name: "pan", label: PIILabel_PANNumber, want: true},
		{name: "email", label: PIILabel_Email, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWeightMergeEntity(tt.label); got != tt.want {
				t.Fatalf("IsWeightMergeEntity(%q)=%v want %v", tt.label, got, tt.want)
			}
		})
	}
}

func TestNewPhase2PermissiveColumnContext(t *testing.T) {
	phase2 := NewPhase2PermissiveColumnContext()
	want := []PIILabel{
		PIILabel_Phone,
		PIILabel_VoterID,
		PIILabel_PassportNumber,
		PIILabel_TAN,
		PIILabel_DrivingLicenceNumber,
	}
	if len(phase2) != len(want) {
		t.Fatalf("phase2 context size=%d want %d: %#v", len(phase2), len(want), phase2)
	}
	for _, label := range want {
		if !phase2[label] {
			t.Fatalf("phase2 context missing %q", label)
		}
	}
	if phase2[PIILabel_CVV] || phase2[PIILabel_ChequeNumber] {
		t.Fatalf("phase2 context should not include discarded noisy entities: %#v", phase2)
	}
}
