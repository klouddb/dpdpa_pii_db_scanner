package piiscanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildHTMLData_SuppressesLowConfidenceByDefault(t *testing.T) {
	output := &DatabasePIIScanOutput{
		Data: map[string]TableDetailOutput{
			"users": {
				"email": {{
					Label:            PIILabel_Email,
					Confidence:       "High",
					ConfidenceIcon:   "🔴",
					DetectorType:     DetectorType_ValueDetector,
					DetectorName:     "regex",
					MatchedCount:     9,
					ScanedValueCount: 10,
				}},
				"notes": {{
					Label:            PIILabel_Name,
					Confidence:       "Low",
					ConfidenceIcon:   "🔵",
					DetectorType:     DetectorType_ValueDetector,
					DetectorName:     "regex",
					MatchedCount:     1,
					ScanedValueCount: 10,
				}},
				"pan_col": {{
					Label:          PIILabel_PANNumber,
					Confidence:     "Medium",
					ConfidenceIcon: "🟡",
					DetectorType:   DetectorType_ColumnDetector,
					DetectorName:   "column",
				}},
			},
		},
	}

	tests := []struct {
		name              string
		printAll          bool
		wantHighData      int
		wantHighMeta      int
		wantLowData       int
		wantLowMeta       int
		wantShowLow       bool
		wantTableCount    int
	}{
		{
			name:           "default suppresses low and medium",
			printAll:       false,
			wantHighData:   1,
			wantHighMeta:   0,
			wantLowData:    0,
			wantLowMeta:    0,
			wantShowLow:    false,
			wantTableCount: 1,
		},
		{
			name:           "print-all includes low and medium",
			printAll:       true,
			wantHighData:   1,
			wantHighMeta:   0,
			wantLowData:    1,
			wantLowMeta:    1,
			wantShowLow:    true,
			wantTableCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cnf := Config{
				Database:        "testdb",
				printAllResults: tt.printAll,
			}
			got := buildHTMLData(output, cnf, "localhost")
			if got.ShowLowConfidence != tt.wantShowLow {
				t.Fatalf("ShowLowConfidence = %v, want %v", got.ShowLowConfidence, tt.wantShowLow)
			}
			if got.DataCount != tt.wantHighData {
				t.Fatalf("DataCount = %d, want %d", got.DataCount, tt.wantHighData)
			}
			if got.MetaCount != tt.wantHighMeta {
				t.Fatalf("MetaCount = %d, want %d", got.MetaCount, tt.wantHighMeta)
			}
			if got.LowDataCount != tt.wantLowData {
				t.Fatalf("LowDataCount = %d, want %d", got.LowDataCount, tt.wantLowData)
			}
			if got.LowMetaCount != tt.wantLowMeta {
				t.Fatalf("LowMetaCount = %d, want %d", got.LowMetaCount, tt.wantLowMeta)
			}
			if got.TableCount != tt.wantTableCount {
				t.Fatalf("TableCount = %d, want %d", got.TableCount, tt.wantTableCount)
			}
		})
	}
}

func TestCreateTabularOutputfile_SuppressesLowConfidenceByDefault(t *testing.T) {
	output := &DatabasePIIScanOutput{
		Data: map[string]TableDetailOutput{
			"users": {
				"email": {{
					Label:          PIILabel_Email,
					Confidence:     "High",
					ConfidenceIcon: "🔴",
					DetectorType:   DetectorType_ColumnDetector,
					DetectorName:   "column",
				}},
				"notes": {{
					Label:          PIILabel_Name,
					Confidence:     "Low",
					ConfidenceIcon: "🔵",
					DetectorType:   DetectorType_ColumnDetector,
					DetectorName:   "column",
				}},
			},
		},
	}

	tests := []struct {
		name           string
		printAll       bool
		wantHighLog    bool
		wantLowLog     bool
	}{
		{
			name:        "default writes high log only",
			printAll:    false,
			wantHighLog: true,
			wantLowLog:  false,
		},
		{
			name:        "print-all writes both logs",
			printAll:    true,
			wantHighLog: true,
			wantLowLog:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.Chdir(cwd)
			})

			cnf := Config{printAllResults: tt.printAll}
			CreateTabularOutputfile(output, cnf)

			highPath := filepath.Join(dir, "kshield_pii_highconfidence.log")
			lowPath := filepath.Join(dir, "kshield_pii_lowconfidence.log")

			if _, err := os.Stat(highPath); (err == nil) != tt.wantHighLog {
				t.Fatalf("high log exists=%v, want %v (err=%v)", err == nil, tt.wantHighLog, err)
			}
			if _, err := os.Stat(lowPath); (err == nil) != tt.wantLowLog {
				t.Fatalf("low log exists=%v, want %v (err=%v)", err == nil, tt.wantLowLog, err)
			}
		})
	}
}
