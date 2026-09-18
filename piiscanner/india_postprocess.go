package piiscanner

import (
	"context"
)

// FallbackFinding is a portable Phase-2 result for consumers that use
// their own report types (e.g. klouddbshield).
type FallbackFinding struct {
	Label        string
	Weight       float64
	MatchedCount int
	ScannedCount int
}

// MergeIndiaValueWeight applies India column+value weight-merge policy.
// If label is not a weight-merge entity, valueWeight is returned unchanged.
func MergeIndiaValueWeight(label string, columnWeight, valueWeight float64) float64 {
	if !IsWeightMergeEntity(PIILabel(label)) {
		return valueWeight
	}
	if columnWeight >= 0.4 {
		return (columnWeight + valueWeight) / 2
	}
	return valueWeight
}

// RunIndiaUnrecognizedColumnFallbacks runs Phase-2 for columns whose names did
// not match any column detector. Returns nil when hasColumnMatch is true or
// sampleVals is empty.
//
// existingColumnLabels are Phase-1 labels already present on the column (skip duplicates).
func RunIndiaUnrecognizedColumnFallbacks(
	ctx context.Context,
	sampleVals []string,
	hasColumnMatch bool,
	existingColumnLabels []string,
) ([]FallbackFinding, error) {
	if hasColumnMatch || len(sampleVals) == 0 {
		return nil, nil
	}

	existing := make(map[PIILabel]bool, len(existingColumnLabels))
	for _, l := range existingColumnLabels {
		existing[PIILabel(l)] = true
	}

	return runIndiaPhase2Fallback(ctx, sampleVals, existing)
}

func runIndiaPhase2Fallback(
	ctx context.Context,
	sampleVals []string,
	existing map[PIILabel]bool,
) ([]FallbackFinding, error) {
	fallbackDetector := NewRegexValueDetectorForRegion(RegionIndia)
	if err := fallbackDetector.Init(); err != nil {
		return nil, err
	}

	fallbackContext := NewPhase2PermissiveColumnContext()
	labelHits := make(map[PIILabel]int)
	labelWeights := make(map[PIILabel]float64)

	for _, val := range sampleVals {
		labels, _ := fallbackDetector.Detect(ctx, val, fallbackContext)
		for _, lbl := range labels {
			labelHits[lbl.PIILabel]++
			labelWeights[lbl.PIILabel] += lbl.Weight
		}
	}

	totalSamples := len(sampleVals)
	const phase2DensityThreshold = 0.30

	var out []FallbackFinding
	for lbl, hits := range labelHits {
		if hits == 0 || existing[lbl] {
			continue
		}
		density := float64(hits) / float64(totalSamples)
		if density < phase2DensityThreshold {
			continue
		}
		avgWeight := labelWeights[lbl] / float64(totalSamples)
		if avgWeight >= 0.70 {
			avgWeight = 0.69
		}
		out = append(out, FallbackFinding{
			Label:        string(lbl),
			Weight:       avgWeight,
			MatchedCount: hits,
			ScannedCount: totalSamples,
		})
	}
	return out, nil
}
