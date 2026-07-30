package piiscanner

import "context"

type PIILabel string

// ColumnContext contains all PII labels detected from the column name.
// Example:
//
//	aadhaar_raw  -> {AdharcardNumber: true}
//	uan_number   -> {UAN: true}
//	pan_number   -> {PANNumber: true}
type ColumnContext map[PIILabel]bool

const (
	PIILabel_Name        PIILabel = "Name"
	PIILabel_Email       PIILabel = "Email"
	PIILabel_Phone       PIILabel = "Phone"
	PIILabel_Address     PIILabel = "Address"
	PIILabel_BirthDate   PIILabel = "BirthDate"
	PIILabel_CreditCard  PIILabel = "CreditCard"
	PIILabel_Password    PIILabel = "Password"
	PIILabel_IPAddress   PIILabel = "IPAddress"
	PIILabel_MacAddress  PIILabel = "MacAddress"
	PIILabel_OAuthToken  PIILabel = "OAuthToken"
	PIILabel_Location    PIILabel = "Location"
	PIILabel_Nationality PIILabel = "Nationality"
	PIILabel_Gender      PIILabel = "Gender"
	PIILabel_Username    PIILabel = "Username"
	PIILabel_UPIID       PIILabel = "UPIID"
	PIILabel_CVV         PIILabel = "CVV"
	PIILabel_TAN         PIILabel = "TAN"
	PIILabel_CIN         PIILabel = "CIN"
	PIILabel_MICRCode    PIILabel = "MICRCode"
	PIILabel_ABHANumber  PIILabel = "ABHANumber"
	PIILabel_UAN         PIILabel = "UAN"
	PIILabel_EPFMemberID PIILabel = "EPFMemberID"

	// PIILabel_BankAccountNumber is pii label for bank account number.
	// currently we are only supporting for india and USA.
	// for this we only have column regex.
	PIILabel_BankAccountNumber PIILabel = "BankAccountNumber"

	// PIILabel_DematAccountNumber is pii label for Demat account number.
	// currently we are only supporting for india.
	// NSDL format is value detectable.
	// CDSL format requires column context.
	PIILabel_DematAccountNumber PIILabel = "DematAccountNumber"

	// PIILabel_PANNumber is pii label for PAN number.
	// currently we are only supporting for india. for this we have column and value regex.
	PIILabel_PANNumber PIILabel = "PANNumber"

	// PIILabel_AdharcardNumber is pii label for Adharcard number.
	// currently we are only supporting for india.
	PIILabel_AdharcardNumber PIILabel = "AdharcardNumber"

	// PIILabel_DrivingLicenceNumber is pii label for Driving Licence number.
	PIILabel_DrivingLicenceNumber PIILabel = "DrivingLicenceNumber"

	// PIILabel_GSTIN is pii label for GSTIN number.
	PIILabel_GSTIN PIILabel = "GSTIN"

	// PIILabel_ChequeNumber is the PII label for cheque numbers.
	PIILabel_ChequeNumber PIILabel = "ChequeNumber"

	// PIILabel_CIFNumber is the PII label for Customer Information File (CIF) number.
	PIILabel_CIFNumber PIILabel = "CIFNumber"

	// PIILabel_LoanAccountNumber is the PII label for loan account numbers.
	PIILabel_LoanAccountNumber PIILabel = "LoanAccountNumber"

	// PIILabel_InsurancePolicyNumber is the PII label for insurance policy numbers.
	PIILabel_InsurancePolicyNumber PIILabel = "InsurancePolicyNumber"

	// PIILabel_FASTagID is the PII label for FASTag identifiers.
	PIILabel_FASTagID PIILabel = "FASTagID"

	// PIILabel_VehicleNumber is pii label for Vehicle number.
	PIILabel_VehicleNumber PIILabel = "VehicleNumber"

	// PIILabel_VoterID is pii label for Voter ID.
	PIILabel_VoterID        PIILabel = "VoterID"
	PIILabel_PassportNumber PIILabel = "PassportNumber"

	// PIILabel_IFSC is pii label for Indian Financial System Code.
	PIILabel_IFSC PIILabel = "IFSC"

	// PIILabel_ESIC is the PII label for Employee State Insurance Corporation number.
	PIILabel_ESIC PIILabel = "ESIC"

	// PIILabel_RationCard is the PII label for Ration Card number.
	PIILabel_RationCard PIILabel = "RationCard"

	// PIILabel_SEBIRegistration is the PII label for SEBI Registration number.
	PIILabel_SEBIRegistration PIILabel = "SEBIRegistration"
)

// Detector is implemented by both value detectors and column detectors.
type Detector interface {
	Name() string

	// Init initializes the detector.
	Init() error

	// Detect detects PII in the supplied word.
	//
	// If this detector is a value detector, word is a value.
	// If this detector is a column detector, word is a column name.
	//
	// columnContext contains all labels detected from the column name.
	//
	// Example:
	//   aadhaar_raw  -> {AdharcardNumber:true}
	//   uan_number   -> {UAN:true}
	//   pan_number   -> {PANNumber:true}
	Detect(ctx context.Context, word string, columnContext ColumnContext) ([]PiiLabelWithWeight, error)
}

type PiiLabelWithWeight struct {
	PIILabel PIILabel
	Weight   float64
}
