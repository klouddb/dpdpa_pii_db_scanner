package piiscanner

import (
	"testing"
)

// buildScanner constructs a databasePiiScanner with pre-populated
// TableScanManager output — no real DB needed.
//
//	table:      table name
//	column:     column name
//	colWeight:  weight the column regex gave (simulates column name match)
//	matchCount: how many values matched the value regex
//	totalRows:  total values scanned
//	perHitWeight: weight per value regex hit (e.g. 0.6 for BankAccountNumber)
func buildScanner(table, column string, label PIILabel, colWeight float64, matchCount, totalRows int, perHitWeight float64) *databasePiiScanner {
	tsm := &TableScanManager{
		outputChan: make(chan ScanOutput),
		valueCount: map[string]map[string]int{
			table: {column: totalRows},
		},
		output: map[string]TableScannerOutput{
			table: {
				TableName: table,
				PiiDataMap: map[string]PiiData{
					column: {
						// Column detector result
						ColumnMap: PiiLabelMap{
							"regex": {
								label: WeightWithCount{Weight: colWeight, Count: 1},
							},
						},
						// Value detector result: matchCount hits × perHitWeight
						ValueMap: PiiLabelMap{
							"regex": {
								label: WeightWithCount{
									Weight: float64(matchCount) * perHitWeight,
									Count:  matchCount,
								},
							},
						},
					},
				},
			},
		},
	}

	cnf := &Config{
		runOption: RunOption_DataScan,
		Database:  "testdb",
		Schema:    "public",
	}

	return &databasePiiScanner{
		tableScanManager: tsm,
		cnf:              cnf,
	}
}

func TestWeightMerge(t *testing.T) {
	tests := []struct {
		name           string
		columnWeight   float64
		matchCount     int
		totalRows      int
		perHitWeight   float64
		wantWeight     float64
		wantConfidence string
	}{
		{
			name:           "strong column with very low match rate",
			columnWeight:   1.0,
			matchCount:     1,
			totalRows:      10000,
			perHitWeight:   0.6,
			wantWeight:     0.50003,
			wantConfidence: "Medium",
		},
		{
			name:           "strong column with high match rate",
			columnWeight:   1.0,
			matchCount:     90,
			totalRows:      100,
			perHitWeight:   0.6,
			wantWeight:     0.77,
			wantConfidence: "High",
		},
		{
			name:           "weak column with low match rate",
			columnWeight:   0.5,
			matchCount:     5,
			totalRows:      100,
			perHitWeight:   0.6,
			wantWeight:     0.265,
			wantConfidence: "Low",
		},
		{
			name:           "no column match",
			columnWeight:   0,
			matchCount:     50,
			totalRows:      100,
			perHitWeight:   0.6,
			wantWeight:     0.3,
			wantConfidence: "Low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const table = "public.transactions"
			const column = "bank_account_number"

			scanner := buildScanner(
				table,
				column,
				PIILabel_BankAccountNumber,
				tt.columnWeight,
				tt.matchCount,
				tt.totalRows,
				tt.perHitWeight,
			)

			output, err := scanner.GetResults()
			if err != nil {
				t.Fatalf("get results: %v", err)
			}

			var finding *PIIDataWithWeightString
			for i := range output.Data[table][column] {
				candidate := &output.Data[table][column][i]
				if candidate.DetectorType == DetectorType_ValueDetector {
					finding = candidate
					break
				}
			}
			if finding == nil {
				t.Fatal("expected value detector finding")
			}

			const tolerance = 0.000001
			if difference := finding.Weight - tt.wantWeight; difference < -tolerance || difference > tolerance {
				t.Errorf("weight: got %.6f, want %.6f", finding.Weight, tt.wantWeight)
			}
			if finding.Confidence != tt.wantConfidence {
				t.Errorf("confidence: got %q, want %q", finding.Confidence, tt.wantConfidence)
			}
		})
	}
}
