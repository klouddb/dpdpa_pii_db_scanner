package piiscanner

import (
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
)

var (
	ignoreRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(created|updated|deleted|committed)_(at|by|on)$`),
		// regexp.MustCompile(`(?i)_id$`), // this is failing. here we need to all _id accept email_id
		regexp.MustCompile(`(?i)^.*timestamp.*$`),
		regexp.MustCompile(`(?i)^(created|updated|modified|deleted|committed|inserted|last_modified|expiry|expiration|effective|issue|invoice|payment)_date$`),
		regexp.MustCompile(`(?i)_time$`),
	}
	ignoreSet = utils.NewSetFromSlice([]string{
		"user_agent",
		"id",
	})
)

type RunOption int

type DetectorType string

const (
	// RunOption_Unset is the zero value of RunOption. It is never a valid,
	// user-selectable scan mode — it only means "no fixed mode was set on
	// this value yet". Config.AutoDetect is what actually signals automatic
	// per-table behavior; never add a `== RunOption_Unset` check to decide
	// scan logic — check AutoDetect instead.
	RunOption_Unset RunOption = iota
	RunOption_MetaScan
	RunOption_DataScan
	RunOption_DeepScan
	RunOption_SpacyScan

	RunOption_MetaScan_String  = "metascan"
	RunOption_DataScan_String  = "datascan"
	RunOption_DeepScan_String  = "deepscan"
	RunOption_SpacyScan_String = "spacyscan"

	RunOption_MetaScan_Title  = "Meta Scan"
	RunOption_DataScan_Title  = "Data Scan"
	RunOption_DeepScan_Title  = "Deep Scan"
	RunOption_SpacyScan_Title = "Spacy Scan"

	// AutoScanTitle is the display label used when Config.AutoDetect is true —
	// there's no single fixed RunOption to describe in that case.
	AutoScanTitle = "Auto Scan"

	DEEPSCAN_WARNINING_LIMIT     = 100000
	DEEPSCAN_SPACY_WARNING_LIMIT = 10000
	AUTO_SCAN_ROW_THRESHOLD      = 10000
	DATASCAN_SAMPLE_SEED         = 47

	DetectorType_ColumnDetector DetectorType = "column detector"
	DetectorType_ValueDetector  DetectorType = "value detector"
)

var OrderMap = map[string]int{
	// for detector type
	string(DetectorType_ValueDetector):  2,
	string(DetectorType_ColumnDetector): 1,

	"regex": 2,
	"spacy": 1,
}

var RunOptionTitleMap = map[RunOption]string{
	RunOption_MetaScan:  RunOption_MetaScan_Title,
	RunOption_DataScan:  RunOption_DataScan_Title,
	RunOption_DeepScan:  RunOption_DeepScan_Title,
	RunOption_SpacyScan: RunOption_SpacyScan_Title,
}

var PiiEntitiesForWeightMergeLogic = utils.NewSetFromSlice([]PIILabel{
	PIILabel_DrivingLicenceNumber,
	PIILabel_CreditCard,
	PIILabel_Phone,
	PIILabel_MICRCode,
	PIILabel_UPIID,
	PIILabel_TAN,
	PIILabel_CIN,
	PIILabel_ChequeNumber,
	PIILabel_LoanAccountNumber,
	PIILabel_InsurancePolicyNumber,
	PIILabel_FASTagID,
	PIILabel_CIFNumber,
	PIILabel_DematAccountNumber,
	PIILabel_PassportNumber,
	PIILabel_VoterID,
	PIILabel_VehicleNumber,
	PIILabel_AdharcardNumber,
	PIILabel_PANNumber,
	PIILabel_GSTIN,
	PIILabel_IFSC,
	PIILabel_BankAccountNumber,
	PIILabel_UPIID,
	PIILabel_ABHANumber,
	PIILabel_UAN,
	PIILabel_EPFMemberID,
	PIILabel_ESIC,
	PIILabel_SEBIRegistration,
	PIILabel_RationCard,
})

var RunOptionMap = map[string]RunOption{
	RunOption_MetaScan_String:  RunOption_MetaScan,
	RunOption_DataScan_String:  RunOption_DataScan,
	RunOption_DeepScan_String:  RunOption_DeepScan,
	RunOption_SpacyScan_String: RunOption_SpacyScan,
}

// IsValidRunOption reports whether s is one of the CLI-selectable scan modes
// (datascan, metascan, deepscan, spacyscan). An empty string deliberately
// returns false here — that case is handled by NewConfig as "no fixed mode
// requested" (auto-detect), not as a run option value.
func IsValidRunOption(s string) bool {
	_, ok := RunOptionMap[s]
	return ok
}

func RunOptionSlice() []string {
	out := make([]string, 0, len(RunOptionMap))
	for k := range RunOptionMap {
		out = append(out, k)
	}
	return out
}

func FilterColumns(columns []string) []string {
	var out []string
	for _, column := range columns {
		if !IgnoreColumn(column) {
			out = append(out, column)
		}
	}
	return out
}

func IgnoreColumn(column string) bool {
	if column == "email_id" {
		return false
	}
	for _, regex := range ignoreRegexes {
		if regex.MatchString(column) {
			return true
		}
	}

	return ignoreSet.Contains(column)
}

func GetValuesString(i interface{}) string {
	switch i := i.(type) {
	case []byte:
		if !utf8.Valid(i) {
			return ""
		}
		return string(i)
	case string:
		return i
	case time.Time:
		return i.Format("2006-01-02")
	default:
		return ""
	}
}
