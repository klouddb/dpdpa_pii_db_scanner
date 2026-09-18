package piiscanner

import "strings"

// IsIndiaRegion reports whether region selects the India/DPDPA detector path.
func IsIndiaRegion(region string) bool {
	return strings.EqualFold(strings.TrimSpace(region), RegionIndia)
}

// NormalizeRegion returns RegionIndia when region is india (any case), otherwise
// the trimmed region string (empty means all/global patterns for ForRegion "").
func NormalizeRegion(region string) string {
	region = strings.TrimSpace(region)
	if IsIndiaRegion(region) {
		return RegionIndia
	}
	return region
}

// NewIndiaColumnDetector returns the India-region column regex detector.
// Consumers (e.g. klouddbshield) should use this instead of wrapping detectors locally.
func NewIndiaColumnDetector() Detector {
	return NewRegexColumnDetectorForRegion(RegionIndia)
}

// NewIndiaValueDetector returns the India-region value regex detector.
func NewIndiaValueDetector() Detector {
	return NewRegexValueDetectorForRegion(RegionIndia)
}

// IsWeightMergeEntity reports whether label participates in column+value weight merge.
// Consumers should call this instead of copying PiiEntitiesForWeightMergeLogic so
// new entities added in this package are picked up on module upgrade.
func IsWeightMergeEntity(label PIILabel) bool {
	return PiiEntitiesForWeightMergeLogic.Contains(label)
}

// WeightMergeLabels returns a snapshot of labels used for column+value weight merge.
func WeightMergeLabels() []PIILabel {
	return PiiEntitiesForWeightMergeLogic.Slice()
}

// NewPhase2PermissiveColumnContext returns the limited Phase-2 unrecognized-column
// fallback context. Only a small set of entities participate to avoid noise.
func NewPhase2PermissiveColumnContext() ColumnContext {
	return ColumnContext{
		PIILabel_Phone:                true,
		PIILabel_VoterID:              true,
		PIILabel_PassportNumber:       true,
		PIILabel_TAN:                  true,
		PIILabel_DrivingLicenceNumber: true,
	}
}
