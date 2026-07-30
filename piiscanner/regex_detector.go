package piiscanner

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
)

func luhnValid(number string) bool {
	sum := 0
	alternate := false

	for i := len(number) - 1; i >= 0; i-- {
		d := int(number[i] - '0')

		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}

		sum += d
		alternate = !alternate
	}

	return sum%10 == 0
}

// RegionIndia loads Indian PII entities (Aadhaar, PAN, DL, Passport, VoterID, etc.).
const RegionIndia = "india"

type RegexWithWeight struct {
	Regexp                *regexp.Regexp
	Weight                float64
	Region                string // empty means global
	RequiresColumnContext bool   // if true, only activates when column name also matches
}

var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// for aadhaar validation
func verhoeffValid(num string) bool {
	c := 0
	for i, j := len(num)-1, 0; i >= 0; i, j = i-1, j+1 {
		digit := int(num[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}
		c = verhoeffD[c][verhoeffP[j%8][digit]]
	}
	return c == 0
}

func ipv4Valid(ip string) bool {

	host := ip

	if strings.Contains(ip, ":") {
		if h, _, err := net.SplitHostPort(ip); err == nil {
			host = h
		}
	}

	return net.ParseIP(host) != nil
}

func ipv6Valid(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// gstinValid validates a GSTIN using the mod-36 check digit algorithm
func gstinValid(gstin string) bool {
	if len(gstin) != 15 {
		return false
	}
	gstin = strings.ToUpper(gstin)
	chars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charMap := make(map[byte]int)
	for i, c := range chars {
		charMap[byte(c)] = i
	}
	sum := 0
	for i := 0; i < 14; i++ {
		val, ok := charMap[gstin[i]]
		if !ok {
			return false
		}
		if i%2 == 0 {
			sum += val
		} else {
			product := val * 2
			sum += product/36 + product%36
		}
	}
	checkVal := (36 - sum%36) % 36
	expectedCheck := chars[checkVal]
	return gstin[14] == expectedCheck
}

// baseRegexDetector is a base helper for regex detectors.
// It contains a map of PIILabel for list of regexes. And also check
// all regexes for each PIILabel and return the first match.
//
// To Create Any new regex detector, you can embed this struct and
// implement Init() method which populate the map with PIILabel and
// list of regexes.

type baseRegexDetector struct {
	m                map[PIILabel][]RegexWithWeight
	isColumnDetector bool
}

func (r *baseRegexDetector) Name() string {
	return "regex"
}
func regionMatches(entryRegion, detectorRegion string) bool {
	// if detector has no region set, load everything
	if detectorRegion == "" {
		return true
	}
	// if entry has no region, it's global — always load
	if entryRegion == "" {
		return true
	}
	// load if regions match
	return entryRegion == detectorRegion
}
func (r *baseRegexDetector) filterByRegion(region string) {
	if region == "" {
		return // no filtering needed, load everything
	}
	filtered := make(map[PIILabel][]RegexWithWeight)
	for label, regexes := range r.m {
		var kept []RegexWithWeight
		for _, rx := range regexes {
			if regionMatches(rx.Region, region) {
				kept = append(kept, rx)
			}
		}
		if len(kept) > 0 {
			filtered[label] = kept
		}
	}
	r.m = filtered
}

// Detect checks the word against all regexes for each PIILabel and
// returns the first match.
func (r *baseRegexDetector) Detect(ctx context.Context, word string, columnContext ColumnContext) ([]PiiLabelWithWeight, error) {
	if r.m == nil {
		return nil, fmt.Errorf("regex detector not initialized")
	}

	word = strings.ToLower(word)

	var out []PiiLabelWithWeight

	for label, regexes := range r.m {
		for _, v := range regexes {
			if v.RequiresColumnContext {
				if columnContext == nil || !columnContext[label] {
					continue
				}
			}
			if label == PIILabel_IPAddress {

				if !r.isColumnDetector {
					matches := v.Regexp.FindStringSubmatch(word)

					if len(matches) == 0 {
						continue
					}

					matchedIP := matches[0]
					if len(matches) > 1 {
						matchedIP = matches[1]
					}

					valid := false

					if strings.Contains(matchedIP, ".") {
						valid = ipv4Valid(matchedIP)
					} else {
						valid = ipv6Valid(matchedIP)
					}

					if !valid {
						continue
					}
				} else {
					if !v.Regexp.MatchString(word) {
						continue
					}
				}

				out = append(out, PiiLabelWithWeight{
					PIILabel: label,
					Weight:   v.Weight,
				})

				break
			}
			if v.Regexp.MatchString(word) {
				matched := v.Regexp.FindString(word)
				if !r.isColumnDetector {

					if label == PIILabel_CreditCard {
						cleaned := strings.NewReplacer(
							" ", "",
							"-", "",
							"+", "",
						).Replace(matched)

						if !luhnValid(cleaned) {
							continue
						}
					}
					if label == PIILabel_AdharcardNumber {
						cleaned := strings.NewReplacer(
							" ", "",
							"-", "",
						).Replace(matched)

						if !verhoeffValid(cleaned) {
							continue
						}
					}
					if label == PIILabel_GSTIN {
						cleaned := strings.ToUpper(strings.TrimSpace(matched))
						if !gstinValid(cleaned) {
							continue
						}
					}
					if label == PIILabel_MacAddress {

						if _, err := net.ParseMAC(matched); err != nil {
							continue
						}
					}
				} // end !r.isColumnDetector
				out = append(out, PiiLabelWithWeight{
					PIILabel: label,
					Weight:   v.Weight,
				})

				break
			}
		}
	}

	return out, nil
}

// regexColumnDetector is a detector which uses regexes to detect
// PIILabels for columns.
//
// It uses some common regexes for some known column name patterns.
type regexColumnDetector struct {
	*baseRegexDetector
	region string
}

// NewRegexColumnDetector returns a new regex column detector
func NewRegexColumnDetector() Detector {
	return NewRegexColumnDetectorForRegion("")
}

// NewRegexColumnDetectorForRegion returns a new regex column detector
// that only loads regexes matching the given region.
// Use RegionIndia, or an empty string for all regions.
func NewRegexColumnDetectorForRegion(region string) Detector {
	return &regexColumnDetector{
		baseRegexDetector: &baseRegexDetector{isColumnDetector: true}, // ← add flag
		region:            region,
	}
}

// Init populates the map with PIILabel and list of regexes for
// known column name patterns.
func (r *regexColumnDetector) Init() error {
	r.m = map[PIILabel][]RegexWithWeight{
		PIILabel_Username: {
			{
				// High confidence - unambiguous username/login column names (word-bounded, matches any prefix/suffix).
				// Bare "user"/"login" moved to Medium below — too generic, more often an FK reference than a username value.
				Regexp: regexp.MustCompile(`(?i)\b(username|user[\s_-]?name|login[\s_-]?name|login[\s_-]?user|user[\s_-]?login|loginid|user[\s_-]?code|user[\s_-]?identifier|signin|sign[\s_-]?in|account[\s_-]?user|app[\s_-]?user|web[\s_-]?user|system[\s_-]?user|network[\s_-]?user|portal[\s_-]?user|auth[\s_-]?user|principal[\s_-]?name|user[\s_-]?principal[\s_-]?name|upn)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "user"/"login"/"user_id"/"login_id"; ambiguous (often numeric FK, not a username value)
				Regexp: regexp.MustCompile(`(?i)\b(user|login|user[\s_-]?id|login[\s_-]?id)\b`),
				Weight: 0.5,
			},
		},
		PIILabel_Name: {
			{
				// High confidence - person-name related column names (word-bounded).
				// Bare "person" moved to Medium below — alone it's often an enum/type/FK label, not a name value.
				Regexp: regexp.MustCompile(`(?i)\b(name|first[\s_-]?name|firstname|f[\s_-]?name|given[\s_-]?name|givenname|middle[\s_-]?name|middlename|last[\s_-]?name|lastname|l[\s_-]?name|surname|family[\s_-]?name|familyname|full[\s_-]?name|fullname|display[\s_-]?name|displayname|legal[\s_-]?name|preferred[\s_-]?name|preferredname|maiden[\s_-]?name|maidenname|birth[\s_-]?name|birthname|nick[\s_-]?name|nickname|screen[\s_-]?name|screenname|profile[\s_-]?name|profilename|person[\s_-]?name|personname|contact[\s_-]?name|contactname|employee[\s_-]?name|employeename|customer[\s_-]?name|customername|client[\s_-]?name|clientname|vendor[\s_-]?name|vendorname|supplier[\s_-]?name|suppliername|owner[\s_-]?name|ownername|account[\s_-]?name|accountname|author[\s_-]?name|authorname|candidate[\s_-]?name|candidatename|student[\s_-]?name|studentname|guardian[\s_-]?name|guardianname|father[\s_-]?name|fathername|mother[\s_-]?name|mothername|spouse[\s_-]?name|spousename|nominee[\s_-]?name|nomineename|beneficiary[\s_-]?name|beneficiaryname|organization[\s_-]?name|organisation[\s_-]?name|company[\s_-]?name|business[\s_-]?name|entity[\s_-]?name)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "person"; ambiguous on its own (often an enum/type/FK label)
				Regexp: regexp.MustCompile(`(?i)\b(person)\b`),
				Weight: 0.5,
			},
		},
		PIILabel_Email: {
			{
				// High confidence - email related column names (word-bounded).
				// Bare "mail" moved to Medium below — collides with physical/postal mail.
				Regexp: regexp.MustCompile(`(?i)\b(email|e[\s_-]?mail|email[\s_-]?address|email[\s_-]?addr|emailaddress|mailaddress|mail[\s_-]?address|primary[\s_-]?email|secondary[\s_-]?email|alternate[\s_-]?email|alt[\s_-]?email|personal[\s_-]?email|official[\s_-]?email|work[\s_-]?email|office[\s_-]?email|business[\s_-]?email|company[\s_-]?email|corporate[\s_-]?email|contact[\s_-]?email|user[\s_-]?email|login[\s_-]?email|registered[\s_-]?email|registered[\s_-]?mail|recovery[\s_-]?email|notification[\s_-]?email|email[\s_-]?id|mail[\s_-]?id|emailid|mailid|email[\s_-]?contact)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "mail"; ambiguous (postal/physical mail, not necessarily an email address)
				Regexp: regexp.MustCompile(`(?i)\b(mail)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(email|e[\s_-]?mail|mail).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Phone: {
			{
				// High confidence - phone/mobile/telephone related column names (word-bounded).
				// Bare "contact" removed entirely; bare "cell" moved to Medium below (spreadsheet/biology/prison cell).
				Regexp: regexp.MustCompile(`(?i)\b(phone|phone[\s_-]?number|phone[\s_-]?no|phone[\s_-]?num|phone[\s_-]?id|ph[\s_-]?number|ph[\s_-]?no|mobile|mobile[\s_-]?number|mobile[\s_-]?no|mobile[\s_-]?num|mobile[\s_-]?phone|mobile[\s_-]?contact|cell[\s_-]?phone|cellphone|cell[\s_-]?number|contact[\s_-]?number|contact[\s_-]?no|contact[\s_-]?phone|telephone|tele[\s_-]?phone|telephone[\s_-]?number|telephone[\s_-]?no|telephone[\s_-]?num|tele[\s_-]?phone[\s_-]?number|tele[\s_-]?phone[\s_-]?no|tele[\s_-]?phone[\s_-]?num|tel|tel[\s_-]?number|tel[\s_-]?no|tel[\s_-]?num|landline|land[\s_-]?line|landline[\s_-]?number|office[\s_-]?phone|home[\s_-]?phone|work[\s_-]?phone|business[\s_-]?phone|company[\s_-]?phone|personal[\s_-]?phone|primary[\s_-]?phone|secondary[\s_-]?phone|alternate[\s_-]?phone|alt[\s_-]?phone|emergency[\s_-]?contact|emergency[\s_-]?phone)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "cell"; ambiguous (spreadsheet cell, biology cell, prison cell, telecom cell tower)
				Regexp: regexp.MustCompile(`(?i)\b(cell)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(phone|mobile|telephone|tele[\s_-]?phone|cellphone|cell|landline|tel).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_IPAddress: {
			{
				// High confidence - IP address related column names (word-bounded).
				// Bare "ip" moved to Medium below — collides with "Intellectual Property" in legal/patent schemas.
				Regexp: regexp.MustCompile(`(?i)\b(ip[\s_-]?address|ip[\s_-]?addr|ipaddr|ipaddress|ipv4|ipv6|ip[\s_-]?v4|ip[\s_-]?v6|ipv[\s_-]?4|ipv[\s_-]?6|ipv4[\s_-]?address|ipv6[\s_-]?address|client[\s_-]?ip|clientip|server[\s_-]?ip|serverip|source[\s_-]?ip|sourceip|destination[\s_-]?ip|assigned[\s_-]?ip|destinationip|dest[\s_-]?ip|destip|remote[\s_-]?ip|remoteip|local[\s_-]?ip|localip|public[\s_-]?ip|publicip|private[\s_-]?ip|privateip|host[\s_-]?ip|hostip|gateway[\s_-]?ip|gatewayip|proxy[\s_-]?ip|proxyip|forwarded[\s_-]?ip|forwardedip|origin[\s_-]?ip|originip|request[\s_-]?ip|requestip|sender[\s_-]?ip|senderip|receiver[\s_-]?ip|receiverip|visitor[\s_-]?ip|visitorip|user[\s_-]?ip|userip|device[\s_-]?ip|deviceip|machine[\s_-]?ip|machineip|network[\s_-]?ip|networkip|node[\s_-]?ip|nodeip|endpoint[\s_-]?ip|endpointip|peer[\s_-]?ip|peerip|connection[\s_-]?ip|connectionip|socket[\s_-]?ip|socketip)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "ip"; ambiguous (Intellectual Property in legal/patent schemas)
				Regexp: regexp.MustCompile(`(?i)\b(ip)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(ip[\s_-]?address|ipaddr|ipaddress|ipv4|ipv6|client[\s_-]?ip|server[\s_-]?ip|remote[\s_-]?ip|local[\s_-]?ip|public[\s_-]?ip|private[\s_-]?ip|host[\s_-]?ip|gateway[\s_-]?ip|proxy[\s_-]?ip|request[\s_-]?ip|device[\s_-]?ip|user[\s_-]?ip).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_MacAddress: {
			{
				// High confidence - MAC address related column names (word-bounded).
				// Bare "mac" and "physical_address" moved to Medium below (see note).
				Regexp: regexp.MustCompile(`(?i)\b(mac[\s_-]?address|macaddr|mac[\s_-]?addr|mac[\s_-]?id|macid|mac[\s_-]?identifier|hardware[\s_-]?address|hardwareaddress|ethernet[\s_-]?address|ethernetaddress|ethernet[\s_-]?mac|ethernetmac|device[\s_-]?mac|devicemac|network[\s_-]?mac|networkmac|adapter[\s_-]?mac|adaptermac|interface[\s_-]?mac|interfacemac|nic[\s_-]?mac|nicmac|host[\s_-]?mac|hostmac|client[\s_-]?mac|clientmac|server[\s_-]?mac|servermac|source[\s_-]?mac|sourcemac|destination[\s_-]?mac|destinationmac|dest[\s_-]?mac|destmac|gateway[\s_-]?mac|gatewaymac|router[\s_-]?mac|routermac|switch[\s_-]?mac|switchmac|bssid|ap[\s_-]?mac|access[\s_-]?point[\s_-]?mac|wifi[\s_-]?mac|wireless[\s_-]?mac|bluetooth[\s_-]?mac)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "mac" (collides with Apple "Mac"/OS enum/crypto MAC) and
				// "physical_address" (far more commonly means a home/mailing address than a network MAC)
				Regexp: regexp.MustCompile(`(?i)\b(mac|physical[\s_-]?address|physicaladdress)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(mac[\s_-]?address|macaddr|hardware[\s_-]?address|physical[\s_-]?address|ethernet[\s_-]?mac|device[\s_-]?mac|network[\s_-]?mac|nic[\s_-]?mac|bssid|wifi[\s_-]?mac|bluetooth[\s_-]?mac).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Address: {
			{
				// High confidence - bare "address" as the ENTIRE column name only (anchored).
				// Kept separate from the word-bounded list below so it doesn't fire as a suffix on
				// "ip_address", "mail_address", "mac_address" — those belong to their own entities.
				Regexp: regexp.MustCompile(`(?i)^address$`),
				Weight: 1.0,
			},
			{
				// High confidence - unambiguous address-specific column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(address[\s_-]?line[\s_-]?1|address[\s_-]?line[\s_-]?2|address[\s_-]?line[\s_-]?3|address[\s_-]?1|address[\s_-]?2|address[\s_-]?3|addr|addr[\s_-]?line[\s_-]?1|addr[\s_-]?line[\s_-]?2|street|street[\s_-]?address|street[\s_-]?name|road|road[\s_-]?name|avenue|boulevard|blvd|highway|hwy|sub[\s_-]?district|country|nation|building|building[\s_-]?name|house[\s_-]?number|house[\s_-]?no|flat[\s_-]?number|flat[\s_-]?no|apartment|apartment[\s_-]?number|apt|unit[\s_-]?number|door[\s_-]?number|door[\s_-]?no|plot[\s_-]?number|plot[\s_-]?no|survey[\s_-]?number|survey[\s_-]?no|landmark|near[\s_-]?by|postal[\s_-]?address|mailing[\s_-]?address|residential[\s_-]?address|permanent[\s_-]?address|current[\s_-]?address|office[\s_-]?address|home[\s_-]?address|billing[\s_-]?address|shipping[\s_-]?address|delivery[\s_-]?address|communication[\s_-]?address|correspondence[\s_-]?address)\b`),
				Weight: 1.0,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(street|road|locality|area|district|city|state|province|county|country|borough|postal[\s_-]?address|mailing[\s_-]?address|billing[\s_-]?address|shipping[\s_-]?address|delivery[\s_-]?address).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_PANNumber: {
			{
				// High confidence - PAN related column names (word-bounded).
				// Bare "tax_id"/"tax_identifier"/"tax_number" moved to Medium below — ambiguous even within an
				// India-region scan (could be a GST reference or generic tax field, not specifically PAN).
				Regexp: regexp.MustCompile(`(?i)\b(pan|pan[\s_-]?number|pan[\s_-]?no|pan[\s_-]?num|pan[\s_-]?id|pan[\s_-]?code|pan[\s_-]?card|pan[\s_-]?identifier|pan[\s_-]?details|pan[\s_-]?info|permanent[\s_-]?account[\s_-]?number|permanent[\s_-]?account[\s_-]?no|permanent[\s_-]?account[\s_-]?num|permanent[\s_-]?account[\s_-]?id|permanent[\s_-]?account[\s_-]?code|permanent[\s_-]?account[\s_-]?card|permanent[\s_-]?account[\s_-]?identifier|tax[\s_-]?payer[\s_-]?number|tax[\s_-]?payer[\s_-]?id|tax[\s_-]?payer[\s_-]?identifier|income[\s_-]?tax[\s_-]?number|income[\s_-]?tax[\s_-]?id|income[\s_-]?tax[\s_-]?account|taxpayer[\s_-]?id|taxpayer[\s_-]?identifier|taxpayer[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare tax-identifier terms without a "payer"/"income" qualifier
				Regexp: regexp.MustCompile(`(?i)\b(tax[\s_-]?id|tax[\s_-]?identifier|tax[\s_-]?number)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(pan[\s_-]?number|pan[\s_-]?id|pan[\s_-]?card|permanent[\s_-]?account|tax[\s_-]?payer|income[\s_-]?tax|tax[\s_-]?identifier|tax[\s_-]?number).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_DrivingLicenceNumber: {
			{
				// High confidence - driving-licence column names qualified with a number/id/card suffix, or a
				// full driver/driving phrase (word-bounded). Bare "dl"/"dls"/"dlno" moved to Medium below —
				// "DL" alone is overloaded (download, delivery, digital-learning) in general schemas.
				Regexp: regexp.MustCompile(`(?i)\b(dl[\s_-]?number|dl[\s_-]?num|dl[\s_-]?no|dl[\s_-]?id|dl[\s_-]?card|dl[\s_-]?identifier|driver[\s_-]?lic|driver[\s_-]?lics|driver[\s_-]?license|driver[\s_-]?licenses|driver[\s_-]?licence|driver[\s_-]?licences|drivers[\s_-]?lic|drivers[\s_-]?lics|drivers[\s_-]?license|drivers[\s_-]?licenses|drivers[\s_-]?licence|drivers[\s_-]?licences|driver'[\s_-]?lic|driver'[\s_-]?license|driver'[\s_-]?licence|driver's[\s_-]?lic|driver's[\s_-]?license|driver's[\s_-]?licence|driv[\s_-]?lic|driv[\s_-]?licen|driv[\s_-]?license|driv[\s_-]?licenses|driv[\s_-]?licence|driv[\s_-]?licences|driving[\s_-]?lic|driving[\s_-]?licen|driving[\s_-]?license|driving[\s_-]?licenses|driving[\s_-]?licence|driving[\s_-]?licences|driving[\s_-]?permit|driver[\s_-]?permit|driving[\s_-]?permit[\s_-]?number|driver[\s_-]?license[\s_-]?number|driver[\s_-]?licence[\s_-]?number|driver[\s_-]?license[\s_-]?id|driver[\s_-]?licence[\s_-]?id|driver[\s_-]?license[\s_-]?card|driver[\s_-]?licence[\s_-]?card)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare "dl"/"dls"/"dlno" and bare "licence_number"/"license_no" without a driver qualifier
				Regexp: regexp.MustCompile(`(?i)\b(dl|dls|dlno|licence[\s_-]?number|licence[\s_-]?no|license[\s_-]?number|license[\s_-]?no)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(driver[\s_-]?lic|driver[\s_-]?license|driver[\s_-]?licence|driving[\s_-]?license|driving[\s_-]?licence|driving[\s_-]?permit|dl[\s_-]?number|dl[\s_-]?no|dlno).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_Password: {
			{
				// High confidence - password/credential related column names (word-bounded).
				// Bare "pass" moved to Medium below — collides with "boarding_pass"/"bus_pass"/"gate_pass" or a pass/fail flag.
				Regexp: regexp.MustCompile(`(?i)\b(password|passwd|passphrase|pass[\s_-]?phrase|passkey|pass[\s_-]?key|login[\s_-]?password|login[\s_-]?pass|login[\s_-]?passphrase|user[\s_-]?password|user[\s_-]?pass|account[\s_-]?password|account[\s_-]?pass|admin[\s_-]?password|admin[\s_-]?pass|db[\s_-]?password|database[\s_-]?password|root[\s_-]?password|master[\s_-]?password|credential|credentials|credential[\s_-]?password|auth[\s_-]?password|authentication[\s_-]?password|secret|shared[\s_-]?secret|client[\s_-]?secret|api[\s_-]?secret|access[\s_-]?password|account[\s_-]?secret|pwd)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "pass"; ambiguous (boarding/bus/gate pass, or a pass/fail status column)
				Regexp: regexp.MustCompile(`(?i)\b(pass)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(password|passwd|passphrase|passkey|login[\s_-]?password|user[\s_-]?password|account[\s_-]?password|auth[\s_-]?password|shared[\s_-]?secret|client[\s_-]?secret|api[\s_-]?secret|pwd).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_CreditCard: {
			{
				// High confidence - credit/debit/payment-qualified card column names (word-bounded).
				// Bare "card_number"/"card_no"/"card_num"/"card_id"/"card_details"/"card_info"/"card_data" moved to
				// Medium below — could be a loyalty/membership/library/ID card, not necessarily a payment card.
				Regexp: regexp.MustCompile(`(?i)\b(credit[\s_-]?card|credit[\s_-]?card[\s_-]?number|credit[\s_-]?card[\s_-]?no|credit[\s_-]?card[\s_-]?num|debit[\s_-]?card|debit[\s_-]?card[\s_-]?number|debit[\s_-]?card[\s_-]?no|cc[\s_-]?number|cc[\s_-]?no|cc[\s_-]?num|payment[\s_-]?card|payment[\s_-]?card[\s_-]?number|bank[\s_-]?card|bank[\s_-]?card[\s_-]?number|visa[\s_-]?card|mastercard|rupay[\s_-]?card)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - generic card terms without a payment-network/type qualifier
				Regexp: regexp.MustCompile(`(?i)\b(card[\s_-]?number|card[\s_-]?no|card[\s_-]?num|card[\s_-]?id|card[\s_-]?details|card[\s_-]?info|card[\s_-]?data)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - broad fallback (also covers concatenated names without separators)
				Regexp: regexp.MustCompile(`(?i)^.*(credit[\s_-]?card|debit[\s_-]?card|card[\s_-]?number|cc[\s_-]?number|payment[\s_-]?card|bank[\s_-]?card).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_BirthDate: {
			{
				// High confidence - birth date related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(dob|dob[\s_-]?date|birth[\s_-]?date|birthdate|birth[\s_-]?day|birthday|birth[\s_-]?dt|birth[\s_-]?datetime|birth[\s_-]?time|date[\s_-]?of[\s_-]?birth|date[\s_-]?of[\s_-]?birth[\s_-]?value|date[\s_-]?born|born[\s_-]?date|born[\s_-]?on|birth[\s_-]?on|person[\s_-]?dob|customer[\s_-]?dob|employee[\s_-]?dob|student[\s_-]?dob|client[\s_-]?dob|patient[\s_-]?dob|member[\s_-]?dob|user[\s_-]?dob|candidate[\s_-]?dob|applicant[\s_-]?dob|guardian[\s_-]?dob|child[\s_-]?dob|spouse[\s_-]?dob|nominee[\s_-]?dob|beneficiary[\s_-]?dob)\b`),
				Weight: 1.0,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(dob|birth[\s_-]?date|birthdate|birthday|date[\s_-]?of[\s_-]?birth|date[\s_-]?born|born[\s_-]?date).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Location: {
			{
				// High confidence - GPS/location related column names (word-bounded).
				// Bare "long" moved to Medium below — collides with the "long"/"long int" data-type name.
				Regexp: regexp.MustCompile(`(?i)\b(location|geo[\s_-]?location|geolocation|geo[\s_-]?point|geo[\s_-]?coordinate|geo[\s_-]?coordinates|gps|gps[\s_-]?location|gps[\s_-]?coordinate|gps[\s_-]?coordinates|coordinate|coordinates|coord|coords|latitude|longitude|lat|lng|lat[\s_-]?long|lat[\s_-]?lng|latitude[\s_-]?longitude|latitude[\s_-]?longitude[\s_-]?pair|latitude[\s_-]?coordinate|longitude[\s_-]?coordinate|latitude[\s_-]?value|longitude[\s_-]?value|geo[\s_-]?lat|geo[\s_-]?long|geo[\s_-]?lng|geo[\s_-]?latitude|geo[\s_-]?longitude|x[\s_-]?coordinate|y[\s_-]?coordinate|map[\s_-]?location|map[\s_-]?coordinate|map[\s_-]?coordinates|pin[\s_-]?location|current[\s_-]?location|live[\s_-]?location|device[\s_-]?location|user[\s_-]?location|customer[\s_-]?location|employee[\s_-]?location|client[\s_-]?location|pickup[\s_-]?location|drop[\s_-]?location|dropoff[\s_-]?location|destination[\s_-]?location|source[\s_-]?location|origin[\s_-]?location)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "long"; ambiguous (commonly a data-type name, not longitude)
				Regexp: regexp.MustCompile(`(?i)\b(long)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(location|geolocation|gps[\s_-]?location|gps[\s_-]?coordinate|latitude|longitude|lat[\s_-]?long|lat[\s_-]?lng|geo[\s_-]?coordinate|coordinate|coordinates).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_OAuthToken: {
			{
				// High confidence - OAuth/auth-qualified token column names (word-bounded).
				// Bare "token"/"tokenid"/"token_id" moved to Medium below — too generic
				// (pagination tokens, CSRF tokens, idempotency keys, feature-flag tokens all use that name).
				Regexp: regexp.MustCompile(`(?i)\b(oauth|oauth[\s_-]?token|oauth[\s_-]?access[\s_-]?token|oauth[\s_-]?refresh[\s_-]?token|oauth[\s_-]?bearer[\s_-]?token|oauth[\s_-]?id[\s_-]?token|oauth[\s_-]?token[\s_-]?secret|oauth[\s_-]?consumer[\s_-]?key|oauth[\s_-]?consumer[\s_-]?secret|oauth[\s_-]?client[\s_-]?id|oauth[\s_-]?client[\s_-]?secret|oauth[\s_-]?verifier|oauth[\s_-]?verifier[\s_-]?secret|oauth[\s_-]?code|oauth[\s_-]?authorization[\s_-]?code|oauth[\s_-]?grant[\s_-]?token|oauth[\s_-]?credential|oauth[\s_-]?credentials|oauth[\s_-]?session[\s_-]?token|oauth[\s_-]?auth[\s_-]?token|oauth[\s_-]?auth[\s_-]?code|oauth[\s_-]?token[\s_-]?value|oauth[\s_-]?token[\s_-]?id|oauth[\s_-]?access[\s_-]?key|oauth[\s_-]?secret|access[\s_-]?token|accesstoken|refresh[\s_-]?token|refreshtoken|bearer[\s_-]?token|id[\s_-]?token|user[\s_-]?token|usertoken|auth[\s_-]?token|google[\s_-]?token|google[\s_-]?auth[\s_-]?token|google[\s_-]?token[\s_-]?id|google[\s_-]?tokenid|google[\s_-]?auth[\s_-]?token[\s_-]?id|google[\s_-]?auth[\s_-]?tokenid)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare "token" references; ambiguous without an oauth/auth/access qualifier
				Regexp: regexp.MustCompile(`(?i)\b(token[\s_-]?id|tokenid|token)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - OAuth-specific fallback (avoids generic token collisions)
				Regexp: regexp.MustCompile(`(?i)^.*(oauth|oauth[\s_-]?token|oauth[\s_-]?access[\s_-]?token|oauth[\s_-]?refresh[\s_-]?token|oauth[\s_-]?client[\s_-]?secret|oauth[\s_-]?consumer[\s_-]?secret|oauth[\s_-]?authorization[\s_-]?code).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Nationality: {
			{
				// High confidence - nationality related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(nationality|nationality[\s_-]?code|nationality[\s_-]?id|nationality[\s_-]?type|nationality[\s_-]?status|nationality[\s_-]?name|nationality[\s_-]?value|nationality[\s_-]?desc|nationality[\s_-]?description|country[\s_-]?of[\s_-]?nationality|citizenship|citizen[\s_-]?ship|citizenship[\s_-]?status|citizenship[\s_-]?type|citizenship[\s_-]?code|citizenship[\s_-]?country|country[\s_-]?of[\s_-]?citizenship|national[\s_-]?status|national[\s_-]?identity|national[\s_-]?origin|country[\s_-]?origin|origin[\s_-]?country|user[\s_-]?nationality)\b`),
				Weight: 1.0,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(nationality|country[\s_-]?of[\s_-]?nationality|citizenship|country[\s_-]?of[\s_-]?citizenship|national[\s_-]?origin).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Gender: {
			{
				// High confidence - gender related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(gender|gender[\s_-]?code|gender[\s_-]?id|gender[\s_-]?type|gender[\s_-]?value|gender[\s_-]?identity|gender[\s_-]?description|gender[\s_-]?desc|sex|sex[\s_-]?code|sex[\s_-]?id|sex[\s_-]?type|sex[\s_-]?value|sex[\s_-]?description|sex[\s_-]?desc|biological[\s_-]?sex|assigned[\s_-]?sex|sex[\s_-]?assigned[\s_-]?at[\s_-]?birth|birth[\s_-]?sex|person[\s_-]?gender|customer[\s_-]?gender|employee[\s_-]?gender|student[\s_-]?gender|client[\s_-]?gender|patient[\s_-]?gender|member[\s_-]?gender|user[\s_-]?gender|candidate[\s_-]?gender|applicant[\s_-]?gender|guardian[\s_-]?gender|spouse[\s_-]?gender|nominee[\s_-]?gender|beneficiary[\s_-]?gender)\b`),
				Weight: 1.0,
			},
			{
				// Low confidence - broad fallback
				Regexp: regexp.MustCompile(`(?i)^.*(gender|gender[\s_-]?identity|sex|biological[\s_-]?sex|birth[\s_-]?sex|assigned[\s_-]?sex).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_BankAccountNumber: {
			{
				// High confidence - bank/transaction-qualified account column names (word-bounded).
				// Bare "account_number" and industry-agnostic "X_account" terms moved to Medium below — could be
				// an app/insurance/utility/ERP-ledger account rather than specifically a bank account.
				Regexp: regexp.MustCompile(`(?i)\b(bank[\s_-]?account|bank[\s_-]?account[\s_-]?number|bank[\s_-]?account[\s_-]?num|bank[\s_-]?account[\s_-]?no|bank[\s_-]?account[\s_-]?id|bank[\s_-]?account[\s_-]?identifier|checking[\s_-]?account|checking[\s_-]?account[\s_-]?number|checking[\s_-]?account[\s_-]?num|checking[\s_-]?account[\s_-]?no|savings[\s_-]?account|savings[\s_-]?account[\s_-]?number|savings[\s_-]?account[\s_-]?num|savings[\s_-]?account[\s_-]?no|current[\s_-]?account|current[\s_-]?account[\s_-]?number|current[\s_-]?account[\s_-]?num|current[\s_-]?account[\s_-]?no|deposit[\s_-]?account|deposit[\s_-]?account[\s_-]?number|beneficiary[\s_-]?account|beneficiary[\s_-]?account[\s_-]?number|payee[\s_-]?account|payee[\s_-]?account[\s_-]?number|sender[\s_-]?account|sender[\s_-]?account[\s_-]?number|receiver[\s_-]?account|receiver[\s_-]?account[\s_-]?number|source[\s_-]?account|source[\s_-]?account[\s_-]?number|destination[\s_-]?account|destination[\s_-]?account[\s_-]?number|refund[\s_-]?account|refund[\s_-]?account[\s_-]?number|refund[\s_-]?account[\s_-]?no|refund[\s_-]?account[\s_-]?num|refund[\s_-]?bank[\s_-]?account|refund[\s_-]?bank[\s_-]?account[\s_-]?number|refund[\s_-]?bank[\s_-]?account[\s_-]?no|salary[\s_-]?account|salary[\s_-]?account[\s_-]?number)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - industry-agnostic account terms; need value corroboration
				Regexp: regexp.MustCompile(`(?i)\b(account[\s_-]?number|account[\s_-]?num|account[\s_-]?no|account[\s_-]?id|account[\s_-]?identifier|account[\s_-]?details|account[\s_-]?value|account[\s_-]?code|acct[\s_-]?number|acct[\s_-]?num|acct[\s_-]?no|acct[\s_-]?id|acct[\s_-]?identifier|acnt[\s_-]?number|acnt[\s_-]?num|acnt[\s_-]?no|acc[\s_-]?number|acc[\s_-]?num|acc[\s_-]?no|from[\s_-]?account|to[\s_-]?account|user[\s_-]?account|user[\s_-]?account[\s_-]?number|vendor[\s_-]?account|vendor[\s_-]?account[\s_-]?number|merchant[\s_-]?account|merchant[\s_-]?account[\s_-]?number|supplier[\s_-]?account|supplier[\s_-]?account[\s_-]?number|claim[\s_-]?account|claim[\s_-]?account[\s_-]?number|customer[\s_-]?account|customer[\s_-]?account[\s_-]?number)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - bank account specific fallback (concatenated names without separators)
				Regexp: regexp.MustCompile(`(?i)^.*(bank[\s_-]?account|checking[\s_-]?account|savings[\s_-]?account|current[\s_-]?account|deposit[\s_-]?account|account[\s_-]?number|acct[\s_-]?number).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_DematAccountNumber: {
			{
				// High confidence - demat-qualified column names (word-bounded).
				// Bare "bo_id"/"bo_number"/"bo_account"/"dp_id"/"dp_account" moved to Medium below —
				// "BO" (Business/Back/Branch Office) and "DP" (Display Picture/Data Processing/Down Payment) are overloaded.
				Regexp: regexp.MustCompile(`(?i)\b(demat|demat[\s_-]?account|demat[\s_-]?account[\s_-]?number|demat[\s_-]?account[\s_-]?num|demat[\s_-]?account[\s_-]?no|demat[\s_-]?account[\s_-]?id|demat[\s_-]?account[\s_-]?identifier|demat[\s_-]?number|demat[\s_-]?num|demat[\s_-]?no|demat[\s_-]?id|demat[\s_-]?identifier|demat[\s_-]?acc|demat[\s_-]?acc[\s_-]?number|demat[\s_-]?acc[\s_-]?num|demat[\s_-]?acc[\s_-]?no|beneficiary[\s_-]?owner|beneficiary[\s_-]?owner[\s_-]?id|beneficiary[\s_-]?owner[\s_-]?number|beneficiary[\s_-]?owner[\s_-]?account|beneficiary[\s_-]?owner[\s_-]?account[\s_-]?number|depository[\s_-]?participant[\s_-]?id|depository[\s_-]?participant[\s_-]?account|depository[\s_-]?account|depository[\s_-]?account[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare "BO"/"DP" abbreviations; overloaded outside the depository context
				Regexp: regexp.MustCompile(`(?i)\b(bo[\s_-]?id|bo[\s_-]?number|bo[\s_-]?account|bo[\s_-]?account[\s_-]?number|dp[\s_-]?id|dp[\s_-]?identifier|dp[\s_-]?account|dp[\s_-]?account[\s_-]?number)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - Demat specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(demat|demat[\s_-]?account|bo[\s_-]?id|beneficiary[\s_-]?owner|beneficiary[\s_-]?account|dp[\s_-]?id|depository[\s_-]?participant).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_ChequeNumber: {
			{
				// High confidence - "cheque"-spelling terms (unambiguous), plus qualified "check"-spelling terms.
				// Bare "check"/"check_number" etc (American spelling, unqualified) moved to Medium below —
				// "check" alone is heavily overloaded (validation check, checked flag, checklist, quality check).
				Regexp: regexp.MustCompile(`(?i)\b(cheque|cheque[\s_-]?number|cheque[\s_-]?num|cheque[\s_-]?no|cheque[\s_-]?id|cheque[\s_-]?identifier|cheque[\s_-]?serial|cheque[\s_-]?serial[\s_-]?number|cheque[\s_-]?reference|cheque[\s_-]?reference[\s_-]?number|cheque[\s_-]?leaf|cheque[\s_-]?leaf[\s_-]?number|bank[\s_-]?cheque|bank[\s_-]?cheque[\s_-]?number|bank[\s_-]?check|bank[\s_-]?check[\s_-]?number|issued[\s_-]?cheque|issued[\s_-]?cheque[\s_-]?number|issued[\s_-]?check|issued[\s_-]?check[\s_-]?number|payee[\s_-]?cheque|payee[\s_-]?cheque[\s_-]?number|payer[\s_-]?cheque|payer[\s_-]?cheque[\s_-]?number|cheque[\s_-]?details|refund[\s_-]?cheque|refund[\s_-]?cheque[\s_-]?number|refund[\s_-]?cheque[\s_-]?num|refund[\s_-]?cheque[\s_-]?no|refund[\s_-]?check|refund[\s_-]?check[\s_-]?number|refund[\s_-]?check[\s_-]?num|refund[\s_-]?check[\s_-]?no|vendor[\s_-]?cheque|customer[\s_-]?cheque|salary[\s_-]?cheque)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - unqualified "check"-spelling terms; ambiguous with generic validation/checklist usage
				Regexp: regexp.MustCompile(`(?i)\b(check|check[\s_-]?number|check[\s_-]?num|check[\s_-]?no|check[\s_-]?id|check[\s_-]?identifier|check[\s_-]?serial|check[\s_-]?serial[\s_-]?number|check[\s_-]?reference|check[\s_-]?reference[\s_-]?number|check[\s_-]?leaf|check[\s_-]?leaf[\s_-]?number|check[\s_-]?details)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - cheque specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(cheque|cheque[\s_-]?number|check|check[\s_-]?number|bank[\s_-]?cheque|bank[\s_-]?check|cheque[\s_-]?reference|check[\s_-]?reference).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_CIFNumber: {
			{
				// High confidence - CIF-qualified column names (word-bounded).
				// Bare "cif" moved to Medium below — collides with the shipping Incoterm "Cost, Insurance, Freight".
				// Generic "customer_identifier"/"customer_number"/"customer_reference"/"customer_file" also moved
				// to Medium — those are common in non-banking CRM/retail schemas too, not CIF-specific.
				Regexp: regexp.MustCompile(`(?i)\b(cif[\s_-]?number|cif[\s_-]?num|cif[\s_-]?no|cif[\s_-]?id|cif[\s_-]?identifier|cif[\s_-]?code|cif[\s_-]?details|customer[\s_-]?cif|customer[\s_-]?cif[\s_-]?number|customer[\s_-]?cif[\s_-]?num|customer[\s_-]?cif[\s_-]?no|customer[\s_-]?information[\s_-]?file|customer[\s_-]?information[\s_-]?file[\s_-]?number|customer[\s_-]?information[\s_-]?file[\s_-]?id)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare "cif"/"cif_value" (Incoterm collision) and generic customer-reference terms
				Regexp: regexp.MustCompile(`(?i)\b(cif|cif[\s_-]?value|customer[\s_-]?identifier|customer[\s_-]?identifier[\s_-]?number|customer[\s_-]?identifier[\s_-]?id|customer[\s_-]?number|customer[\s_-]?number[\s_-]?id|customer[\s_-]?number[\s_-]?code|customer[\s_-]?reference|customer[\s_-]?reference[\s_-]?number|customer[\s_-]?reference[\s_-]?id|customer[\s_-]?reference[\s_-]?code|customer[\s_-]?file|customer[\s_-]?file[\s_-]?number)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - CIF specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(cif|customer[\s_-]?cif|customer[\s_-]?information[\s_-]?file|customer[\s_-]?identifier).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_LoanAccountNumber: {
			{
				// High confidence - loan account related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(loan|loan[\s_-]?account|loan[\s_-]?account[\s_-]?number|loan[\s_-]?account[\s_-]?num|loan[\s_-]?account[\s_-]?no|loan[\s_-]?account[\s_-]?id|loan[\s_-]?account[\s_-]?identifier|loan[\s_-]?number|loan[\s_-]?num|loan[\s_-]?no|loan[\s_-]?id|loan[\s_-]?identifier|loan[\s_-]?acc|loan[\s_-]?acc[\s_-]?number|loan[\s_-]?acc[\s_-]?num|loan[\s_-]?acc[\s_-]?no|loan[\s_-]?acct|loan[\s_-]?acct[\s_-]?number|loan[\s_-]?acct[\s_-]?num|loan[\s_-]?acct[\s_-]?no|loan[\s_-]?reference|loan[\s_-]?reference[\s_-]?number|loan[\s_-]?reference[\s_-]?id|loan[\s_-]?reference[\s_-]?code|loan[\s_-]?contract|loan[\s_-]?contract[\s_-]?number|loan[\s_-]?contract[\s_-]?id|loan[\s_-]?agreement|loan[\s_-]?agreement[\s_-]?number|loan[\s_-]?agreement[\s_-]?id|loan[\s_-]?application|loan[\s_-]?application[\s_-]?number|loan[\s_-]?application[\s_-]?id|borrower[\s_-]?loan[\s_-]?account|borrower[\s_-]?loan[\s_-]?number|customer[\s_-]?loan[\s_-]?account|customer[\s_-]?loan[\s_-]?number|home[\s_-]?loan[\s_-]?account|vehicle[\s_-]?loan[\s_-]?account|personal[\s_-]?loan[\s_-]?account|education[\s_-]?loan[\s_-]?account|gold[\s_-]?loan[\s_-]?account|mortgage[\s_-]?loan[\s_-]?account)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - loan account specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(loan[\s_-]?account|loan[\s_-]?number|loan[\s_-]?reference|loan[\s_-]?contract|loan[\s_-]?agreement|loan[\s_-]?application).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_InsurancePolicyNumber: {
			{
				// High confidence - insurance-qualified policy column names (word-bounded).
				// Bare "policy"/"policy_number"/"policy_reference"/"policy_certificate"/"policy_document" moved to
				// Medium below — "policy" alone is heavily overloaded (IT policy, HR policy, firewall/retention policy).
				Regexp: regexp.MustCompile(`(?i)\b(insurance[\s_-]?policy|insurance[\s_-]?policy[\s_-]?number|insurance[\s_-]?policy[\s_-]?num|insurance[\s_-]?policy[\s_-]?no|insurance[\s_-]?policy[\s_-]?id|insurance[\s_-]?policy[\s_-]?identifier|life[\s_-]?policy|life[\s_-]?policy[\s_-]?number|health[\s_-]?policy|health[\s_-]?policy[\s_-]?number|medical[\s_-]?policy|medical[\s_-]?policy[\s_-]?number|motor[\s_-]?policy|motor[\s_-]?policy[\s_-]?number|vehicle[\s_-]?policy|vehicle[\s_-]?policy[\s_-]?number|car[\s_-]?policy|car[\s_-]?policy[\s_-]?number|travel[\s_-]?policy|travel[\s_-]?policy[\s_-]?number|home[\s_-]?policy|home[\s_-]?policy[\s_-]?number|fire[\s_-]?policy|fire[\s_-]?policy[\s_-]?number|group[\s_-]?policy|group[\s_-]?policy[\s_-]?number|policy[\s_-]?holder[\s_-]?number|insured[\s_-]?policy|insured[\s_-]?policy[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare/generic policy terms without a domain qualifier
				Regexp: regexp.MustCompile(`(?i)\b(policy|policy[\s_-]?number|policy[\s_-]?num|policy[\s_-]?no|policy[\s_-]?id|policy[\s_-]?identifier|policy[\s_-]?code|policy[\s_-]?reference|policy[\s_-]?reference[\s_-]?number|policy[\s_-]?reference[\s_-]?id|policy[\s_-]?certificate|policy[\s_-]?certificate[\s_-]?number|policy[\s_-]?certificate[\s_-]?id|policy[\s_-]?document|policy[\s_-]?document[\s_-]?number)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - insurance policy specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(insurance[\s_-]?policy|policy[\s_-]?number|policy[\s_-]?reference|policy[\s_-]?certificate|life[\s_-]?policy|health[\s_-]?policy|motor[\s_-]?policy).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_FASTagID: {
			{
				// High confidence - FASTag/toll-qualified column names (word-bounded).
				// Bare "tag_id"/"tag_number"/"tag_identifier" moved to Medium below — generic tagging/RFID/metadata systems.
				Regexp: regexp.MustCompile(`(?i)\b(fastag|fastag[\s_-]?id|fastag[\s_-]?identifier|fastag[\s_-]?number|fastag[\s_-]?num|fastag[\s_-]?no|fastag[\s_-]?code|fastag[\s_-]?account|fastag[\s_-]?account[\s_-]?number|fastag[\s_-]?account[\s_-]?id|fastag[\s_-]?wallet|fastag[\s_-]?wallet[\s_-]?id|fastag[\s_-]?wallet[\s_-]?number|fastag[\s_-]?customer|fastag[\s_-]?customer[\s_-]?id|fastag[\s_-]?customer[\s_-]?number|fastag[\s_-]?reference|fastag[\s_-]?reference[\s_-]?number|fastag[\s_-]?reference[\s_-]?id|fastag[\s_-]?serial|fastag[\s_-]?serial[\s_-]?number|fastag[\s_-]?tag|fastag[\s_-]?tag[\s_-]?id|fastag[\s_-]?tag[\s_-]?number|toll[\s_-]?tag|toll[\s_-]?tag[\s_-]?id|toll[\s_-]?tag[\s_-]?number|electronic[\s_-]?toll[\s_-]?tag|electronic[\s_-]?toll[\s_-]?tag[\s_-]?id|electronic[\s_-]?toll[\s_-]?tag[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare tag terms; ambiguous with generic tagging/RFID/metadata systems
				Regexp: regexp.MustCompile(`(?i)\b(tag[\s_-]?id|tag[\s_-]?number|tag[\s_-]?identifier)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - FASTag specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(fastag|fastag[\s_-]?id|fastag[\s_-]?number|fastag[\s_-]?tag|toll[\s_-]?tag|electronic[\s_-]?toll[\s_-]?tag).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_UPIID: {
			{
				// High confidence - UPI/VPA related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(upi|upi[\s_-]?id|upi[\s_-]?identifier|upi[\s_-]?number|upi[\s_-]?handle|upi[\s_-]?address|upi[\s_-]?account|upi[\s_-]?account[\s_-]?id|upi[\s_-]?account[\s_-]?handle|upi[\s_-]?account[\s_-]?identifier|upi[\s_-]?vpa|vpa|vpa[\s_-]?id|vpa[\s_-]?identifier|vpa[\s_-]?handle|vpa[\s_-]?address|virtual[\s_-]?payment[\s_-]?address|virtual[\s_-]?payment[\s_-]?identifier|virtual[\s_-]?payment[\s_-]?id|payment[\s_-]?address|payment[\s_-]?handle|payment[\s_-]?vpa|bhim[\s_-]?upi|bhim[\s_-]?id|bhim[\s_-]?handle|merchant[\s_-]?upi|merchant[\s_-]?upi[\s_-]?id|merchant[\s_-]?vpa|payee[\s_-]?upi|payee[\s_-]?vpa|payer[\s_-]?upi|payer[\s_-]?vpa|receiver[\s_-]?upi|receiver[\s_-]?vpa|beneficiary[\s_-]?upi|beneficiary[\s_-]?vpa)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - UPI specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(upi[\s_-]?id|upi[\s_-]?handle|upi[\s_-]?vpa|vpa|virtual[\s_-]?payment[\s_-]?address|merchant[\s_-]?upi|bhim[\s_-]?upi).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_CVV: {
			{
				// High confidence - card-qualified CVV/CVC/CVN column names (word-bounded).
				// Bare "cid"/"csc" moved to Medium below in addition to the earlier verification/security-code demotion —
				// "csc" collides with India's Common Service Centre scheme; "cid" collides with Customer/Case/Content ID.
				Regexp: regexp.MustCompile(`(?i)\b(cvv|cvv[\s_-]?code|cvv[\s_-]?number|cvv[\s_-]?value|cvv[\s_-]?id|cvc|cvc[\s_-]?code|cvc[\s_-]?number|cvc[\s_-]?value|cvc[\s_-]?id|cvn|cvn[\s_-]?code|cvn[\s_-]?number|cvn[\s_-]?value|card[\s_-]?cvv|card[\s_-]?cvc|card[\s_-]?cid|card[\s_-]?cvn|card[\s_-]?csc|card[\s_-]?verification[\s_-]?value|card[\s_-]?verification[\s_-]?code|card[\s_-]?security[\s_-]?code|card[\s_-]?security[\s_-]?value|card[\s_-]?validation[\s_-]?code|payment[\s_-]?card[\s_-]?cvv|payment[\s_-]?card[\s_-]?cvc|payment[\s_-]?card[\s_-]?security[\s_-]?code)\b`),
				Weight: 1.0,
			},
			{
				// Medium confidence - bare verification/security-code terms, plus bare "cid"/"csc"
				Regexp: regexp.MustCompile(`(?i)\b(verification[\s_-]?value|verification[\s_-]?code|security[\s_-]?code|security[\s_-]?value|cid|csc)\b`),
				Weight: 0.5,
			},
			{
				// Low confidence - CVV specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(cvv|cvc|cid|cvn|csc|card[\s_-]?verification[\s_-]?code|card[\s_-]?security[\s_-]?code|verification[\s_-]?value|security[\s_-]?value).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_TAN: {
			{
				// High confidence - bare "tan" as the ENTIRE column name only (anchored).
				// Kept separate from the word-bounded list below so it doesn't fire as a suffix on
				Regexp: regexp.MustCompile(`(?i)^tan$`),
				Weight: 1.0,
			},
			{
				// High confidence - TAN column names qualified with a number/id/code suffix or a tax/TDS/TCS phrase.
				// Bare "tan" and generic "tax_account"/"tax_account_number" moved to Medium below —
				// "tan" collides with suntan and the trigonometric function; "tax_account" is generic ledger terminology.
				Regexp: regexp.MustCompile(`(?i)\b(tan[\s_-]?number|tan[\s_-]?num|tan[\s_-]?no|tan[\s_-]?id|tan[\s_-]?identifier|tan[\s_-]?code|tax[\s_-]?deduction[\s_-]?account[\s_-]?number|tax[\s_-]?deduction[\s_-]?account|tax[\s_-]?collection[\s_-]?account[\s_-]?number|tax[\s_-]?collection[\s_-]?account|tds[\s_-]?tan|tds[\s_-]?tan[\s_-]?number|tds[\s_-]?account[\s_-]?number|tds[\s_-]?account|tcs[\s_-]?tan|tcs[\s_-]?tan[\s_-]?number|tcs[\s_-]?account[\s_-]?number|tcs[\s_-]?account|deductor[\s_-]?tan|deductor[\s_-]?tan[\s_-]?number|deductor[\s_-]?account[\s_-]?number|collector[\s_-]?tan|collector[\s_-]?tan[\s_-]?number|collector[\s_-]?account[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare "tan" and generic tax-account terms
				Regexp: regexp.MustCompile(`(?i)\b(tax[\s_-]?account[\s_-]?number|tax[\s_-]?account)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - TAN specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(tds[\s_-]?tan|tcs[\s_-]?tan|tax[\s_-]?deduction[\s_-]?account|tax[\s_-]?collection[\s_-]?account|deductor[\s_-]?tan|collector[\s_-]?tan).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_CIN: {
			{
				// High confidence - bare "CIN" as the ENTIRE column name only (anchored).
				// Kept separate from the word-bounded list below so it doesn't fire as a suffix on
				Regexp: regexp.MustCompile(`(?i)^cin$`),
				Weight: 1.0,
			},
			{
				// High confidence - company/corporate-qualified CIN column names (word-bounded).
				// Bare "cin"/"cin_number" etc moved to Medium below — could mean a generic "Customer ID Number"
				// outside the corporate-registration context.
				Regexp: regexp.MustCompile(`(?i)\b(company[\s_-]?cin|company[\s_-]?cin[\s_-]?number|company[\s_-]?cin[\s_-]?id|company[\s_-]?identification[\s_-]?number|company[\s_-]?identification[\s_-]?code|corporate[\s_-]?identification[\s_-]?number|corporate[\s_-]?identification[\s_-]?code|corporate[\s_-]?identity[\s_-]?number|corporate[\s_-]?identity[\s_-]?code|corporate[\s_-]?registration[\s_-]?number|company[\s_-]?registration[\s_-]?number|mca[\s_-]?cin|mca[\s_-]?cin[\s_-]?number|roc[\s_-]?cin|roc[\s_-]?cin[\s_-]?number|incorporation[\s_-]?number|incorporation[\s_-]?id|company[\s_-]?incorporation[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare "cin" terms without a company/corporate qualifier
				Regexp: regexp.MustCompile(`(?i)\b(cin|cin[\s_-]?number|cin[\s_-]?num|cin[\s_-]?no|cin[\s_-]?id|cin[\s_-]?identifier|cin[\s_-]?code)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - CIN specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(company[\s_-]?cin|corporate[\s_-]?identification[\s_-]?number|company[\s_-]?identification[\s_-]?number|mca[\s_-]?cin|roc[\s_-]?cin|incorporation[\s_-]?number).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_MICRCode: {
			{
				// High confidence - MICR related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(micr|micr[\s_-]?code|micr[\s_-]?number|micr[\s_-]?num|micr[\s_-]?no|micr[\s_-]?id|micr[\s_-]?identifier|micr[\s_-]?value|micr[\s_-]?line|micr[\s_-]?line[\s_-]?code|micr[\s_-]?routing|bank[\s_-]?micr|bank[\s_-]?micr[\s_-]?code|branch[\s_-]?micr|branch[\s_-]?micr[\s_-]?code|cheque[\s_-]?micr|cheque[\s_-]?micr[\s_-]?code|check[\s_-]?micr|check[\s_-]?micr[\s_-]?code|account[\s_-]?micr|account[\s_-]?micr[\s_-]?code|micr[\s_-]?branch|micr[\s_-]?branch[\s_-]?code|micr[\s_-]?bank|micr[\s_-]?bank[\s_-]?code|magnetic[\s_-]?ink[\s_-]?character[\s_-]?recognition|magnetic[\s_-]?ink[\s_-]?character[\s_-]?recognition[\s_-]?code|magnetic[\s_-]?ink[\s_-]?code)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - MICR specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(micr|bank[\s_-]?micr|branch[\s_-]?micr|cheque[\s_-]?micr|check[\s_-]?micr|magnetic[\s_-]?ink[\s_-]?character[\s_-]?recognition).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_GSTIN: {
			{
				// High confidence - GSTIN related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(gstin|gstin[\s_-]?number|gstin[\s_-]?num|gstin[\s_-]?no|gstin[\s_-]?id|gstin[\s_-]?identifier|gst[\s_-]?registration[\s_-]?number|gst[\s_-]?registration[\s_-]?id|gst[\s_-]?registration[\s_-]?code|gst[\s_-]?number|gst[\s_-]?no|gst[\s_-]?id|gst[\s_-]?identifier|gst[\s_-]?code|goods[\s_-]?and[\s_-]?services[\s_-]?tax[\s_-]?identification[\s_-]?number|goods[\s_-]?and[\s_-]?services[\s_-]?tax[\s_-]?registration[\s_-]?number|goods[\s_-]?services[\s_-]?tax[\s_-]?number|supplier[\s_-]?gstin|supplier[\s_-]?gst|vendor[\s_-]?gstin|vendor[\s_-]?gst|customer[\s_-]?gstin|customer[\s_-]?gst|business[\s_-]?gstin|business[\s_-]?gst|company[\s_-]?gstin|company[\s_-]?gst|dealer[\s_-]?gstin|dealer[\s_-]?gst|firm[\s_-]?gstin|firm[\s_-]?gst|entity[\s_-]?gstin|entity[\s_-]?gst)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - GSTIN specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(gstin|gst[\s_-]?registration|supplier[\s_-]?gstin|vendor[\s_-]?gstin|customer[\s_-]?gstin|company[\s_-]?gstin|goods[\s_-]?and[\s_-]?services[\s_-]?tax).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_AdharcardNumber: {
			{
				// High confidence - Aadhaar related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(aadhaar|aadhaar[\s_-]?number|aadhaar[\s_-]?num|aadhaar[\s_-]?no|aadhaar[\s_-]?id|aadhaar[\s_-]?identifier|aadhaar[\s_-]?card|aadhaar[\s_-]?card[\s_-]?number|aadhaar[\s_-]?uid|aadhaar[\s_-]?uid[\s_-]?number|aadhar|aadhar[\s_-]?number|aadhar[\s_-]?num|aadhar[\s_-]?no|aadhar[\s_-]?id|aadhar[\s_-]?identifier|aadhar[\s_-]?card|aadhar[\s_-]?card[\s_-]?number|aadhar[\s_-]?uid|aadhar[\s_-]?uid[\s_-]?number|adhaar|adhaar[\s_-]?number|adhaar[\s_-]?num|adhaar[\s_-]?no|adhaar[\s_-]?card|adhar|adhar[\s_-]?number|adhar[\s_-]?num|adhar[\s_-]?no|uidai|uidai[\s_-]?number|uidai[\s_-]?id|uidai[\s_-]?identifier|unique[\s_-]?identification[\s_-]?number|unique[\s_-]?identification[\s_-]?id|unique[\s_-]?identity[\s_-]?number|resident[\s_-]?id|resident[\s_-]?identity[\s_-]?number|national[\s_-]?identity[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - Aadhaar specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(aadhaar|aadhar|adhaar|adhar|uidai|unique[\s_-]?identification[\s_-]?number|unique[\s_-]?identity[\s_-]?number).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_PassportNumber: {
			{
				// High confidence - Passport related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(passport|passport[\s_-]?number|passport[\s_-]?num|passport[\s_-]?no|passport[\s_-]?id|passport[\s_-]?identifier|passport[\s_-]?code|passport[\s_-]?card|passport[\s_-]?document|passport[\s_-]?document[\s_-]?number|passport[\s_-]?book|passport[\s_-]?book[\s_-]?number|passport[\s_-]?serial|passport[\s_-]?serial[\s_-]?number|passport[\s_-]?details|passport[\s_-]?info|passport[\s_-]?information|passport[\s_-]?record|passport[\s_-]?reference|passport[\s_-]?reference[\s_-]?number|passport[\s_-]?identifier[\s_-]?number|travel[\s_-]?passport|travel[\s_-]?passport[\s_-]?number|travel[\s_-]?document|travel[\s_-]?document[\s_-]?number|international[\s_-]?passport|international[\s_-]?passport[\s_-]?number|foreign[\s_-]?passport|foreign[\s_-]?passport[\s_-]?number|citizen[\s_-]?passport|citizen[\s_-]?passport[\s_-]?number)\b`),
				Weight: 1.0,
			},
			{
				// Low confidence - Passport specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(passport|travel[\s_-]?passport|travel[\s_-]?document|international[\s_-]?passport|foreign[\s_-]?passport).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_ABHANumber: {
			{
				// High confidence - ABHA/ABDM/Ayushman-qualified column names (word-bounded).
				// Bare "health_id"/"health_number"/"national_health_id" moved to Medium below —
				// collides with the UK's National Health (Service) Number and generic hospital/insurer health-record IDs.
				Regexp: regexp.MustCompile(`(?i)\b(abha|abha[\s_-]?number|abha[\s_-]?num|abha[\s_-]?no|abha[\s_-]?id|abha[\s_-]?identifier|abha[\s_-]?address|abha[\s_-]?card|abha[\s_-]?card[\s_-]?number|abha[\s_-]?health[\s_-]?id|abha[\s_-]?health[\s_-]?identifier|abdm|abdm[\s_-]?id|abdm[\s_-]?identifier|abdm[\s_-]?number|abdm[\s_-]?health[\s_-]?id|ayushman[\s_-]?bharat[\s_-]?health[\s_-]?account|ayushman[\s_-]?bharat[\s_-]?health[\s_-]?account[\s_-]?number|ayushman[\s_-]?health[\s_-]?account|digital[\s_-]?health[\s_-]?id)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare/generic health-ID terms without an ABHA/ABDM/Ayushman qualifier
				Regexp: regexp.MustCompile(`(?i)\b(health[\s_-]?id|health[\s_-]?identifier|health[\s_-]?identity|health[\s_-]?number|health[\s_-]?card[\s_-]?number|health[\s_-]?account|health[\s_-]?account[\s_-]?number|healthid|healthid[\s_-]?number|healthid[\s_-]?identifier|health[\s_-]?unique[\s_-]?id|health[\s_-]?unique[\s_-]?identifier|national[\s_-]?health[\s_-]?id)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - ABHA specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(abha|abdm|abha[\s_-]?health[\s_-]?id|ayushman[\s_-]?bharat[\s_-]?health[\s_-]?account|ayushman[\s_-]?health[\s_-]?account|national[\s_-]?health[\s_-]?id|digital[\s_-]?health[\s_-]?id).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_UAN: {
			{
				// High confidence - UAN related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(uan|uan[\s_-]?number|uan[\s_-]?num|uan[\s_-]?no|uan[\s_-]?id|uan[\s_-]?identifier|uan[\s_-]?code|universal[\s_-]?account[\s_-]?number|universal[\s_-]?account[\s_-]?id|universal[\s_-]?account[\s_-]?identifier|epf[\s_-]?uan|epf[\s_-]?uan[\s_-]?number|epfo[\s_-]?uan|epfo[\s_-]?uan[\s_-]?number|employee[\s_-]?uan|employee[\s_-]?uan[\s_-]?number|employee[\s_-]?pf[\s_-]?uan|employee[\s_-]?provident[\s_-]?fund[\s_-]?uan|provident[\s_-]?fund[\s_-]?uan|pf[\s_-]?uan|member[\s_-]?uan|member[\s_-]?uan[\s_-]?number|uan[\s_-]?member[\s_-]?id|uan[\s_-]?member[\s_-]?number)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - UAN specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(uan|universal[\s_-]?account[\s_-]?number|epf[\s_-]?uan|epfo[\s_-]?uan|employee[\s_-]?uan|provident[\s_-]?fund[\s_-]?uan|pf[\s_-]?uan).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_EPFMemberID: {
			{
				// High confidence - EPF Member ID related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(epf[\s_-]?member|epf[\s_-]?member[\s_-]?id|epf[\s_-]?member[\s_-]?number|epf[\s_-]?member[\s_-]?no|epf[\s_-]?member[\s_-]?num|epf[\s_-]?member[\s_-]?identifier|epf[\s_-]?account|epf[\s_-]?account[\s_-]?number|epf[\s_-]?account[\s_-]?id|epf[\s_-]?account[\s_-]?identifier|epfo[\s_-]?member|epfo[\s_-]?member[\s_-]?id|epfo[\s_-]?member[\s_-]?number|pf[\s_-]?member|pf[\s_-]?member[\s_-]?id|pf[\s_-]?member[\s_-]?number|pf[\s_-]?account|pf[\s_-]?account[\s_-]?number|pf[\s_-]?account[\s_-]?id|provident[\s_-]?fund[\s_-]?member|provident[\s_-]?fund[\s_-]?member[\s_-]?id|provident[\s_-]?fund[\s_-]?member[\s_-]?number|provident[\s_-]?fund[\s_-]?account|provident[\s_-]?fund[\s_-]?account[\s_-]?number|employee[\s_-]?pf[\s_-]?member|employee[\s_-]?pf[\s_-]?member[\s_-]?id|employee[\s_-]?provident[\s_-]?fund[\s_-]?member|employee[\s_-]?provident[\s_-]?fund[\s_-]?member[\s_-]?id|member[\s_-]?pf[\s_-]?number|member[\s_-]?epf[\s_-]?number|pf[\s_-]?member[\s_-]?code|epf[\s_-]?member[\s_-]?code)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - EPF Member ID specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(epf[\s_-]?member|epfo[\s_-]?member|pf[\s_-]?member|provident[\s_-]?fund[\s_-]?member|epf[\s_-]?account|pf[\s_-]?account|provident[\s_-]?fund[\s_-]?account).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_VoterID: {
			{
				// High confidence - voter/electoral-qualified column names (word-bounded).
				// Bare "epic"/"epic_id" etc moved to Medium below — "epic" is extremely common in agile/Jira
				// tooling ("epic_id", "epic_key") and everyday usage ("epic fail"), unrelated to Voter ID.
				Regexp: regexp.MustCompile(`(?i)\b(voter|voter[\s_-]?id|voter[\s_-]?number|voter[\s_-]?num|voter[\s_-]?no|voter[\s_-]?identifier|voter[\s_-]?card|voter[\s_-]?card[\s_-]?number|voter[\s_-]?identity[\s_-]?card|voter[\s_-]?identity[\s_-]?number|voter[\s_-]?registration[\s_-]?number|voter[\s_-]?registration[\s_-]?id|voter[\s_-]?serial[\s_-]?number|elector[\s_-]?id|elector[\s_-]?number|elector[\s_-]?identifier|elector[\s_-]?card|elector[\s_-]?card[\s_-]?number|elector[\s_-]?photo[\s_-]?identity[\s_-]?card|electoral[\s_-]?id|electoral[\s_-]?number|electoral[\s_-]?identifier|electoral[\s_-]?card|electoral[\s_-]?photo[\s_-]?identity[\s_-]?card|electors[\s_-]?photo[\s_-]?identity[\s_-]?card|electors[\s_-]?photo[\s_-]?id|electors[\s_-]?photo[\s_-]?card)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Medium confidence - bare "epic" terms; collides with agile/Jira "epic" and colloquial usage
				Regexp: regexp.MustCompile(`(?i)\b(epic|epic[\s_-]?id|epic[\s_-]?number|epic[\s_-]?num|epic[\s_-]?no|epic[\s_-]?identifier|epic[\s_-]?card|epic[\s_-]?card[\s_-]?number)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				// Low confidence - Voter ID specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(voter[\s_-]?id|voter[\s_-]?card|elector[\s_-]?id|electoral[\s_-]?id|epic|electors[\s_-]?photo[\s_-]?identity[\s_-]?card).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_IFSC: {
			{
				// High confidence - IFSC related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(ifsc|ifsc[\s_-]?code|ifsc[\s_-]?number|ifsc[\s_-]?num|ifsc[\s_-]?no|ifsc[\s_-]?id|ifsc[\s_-]?identifier|ifsc[\s_-]?value|bank[\s_-]?ifsc|bank[\s_-]?ifsc[\s_-]?code|branch[\s_-]?ifsc|branch[\s_-]?ifsc[\s_-]?code|beneficiary[\s_-]?ifsc|beneficiary[\s_-]?ifsc[\s_-]?code|receiver[\s_-]?ifsc|receiver[\s_-]?ifsc[\s_-]?code|payer[\s_-]?ifsc|payer[\s_-]?ifsc[\s_-]?code|payee[\s_-]?ifsc|payee[\s_-]?ifsc[\s_-]?code|customer[\s_-]?ifsc|customer[\s_-]?ifsc[\s_-]?code|account[\s_-]?ifsc|account[\s_-]?ifsc[\s_-]?code|bank[\s_-]?branch[\s_-]?ifsc|bank[\s_-]?branch[\s_-]?code|indian[\s_-]?financial[\s_-]?system[\s_-]?code)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - IFSC specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(ifsc|bank[\s_-]?ifsc|branch[\s_-]?ifsc|beneficiary[\s_-]?ifsc|receiver[\s_-]?ifsc|payer[\s_-]?ifsc|payee[\s_-]?ifsc|customer[\s_-]?ifsc|account[\s_-]?ifsc|indian[\s_-]?financial[\s_-]?system[\s_-]?code).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_ESIC: {
			{
				// High confidence - ESIC related column names (word-bounded).
				// "ip_number"/"ip_id" intentionally excluded — collides with IPAddress; see Low tier below.
				Regexp: regexp.MustCompile(`(?i)\b(esic|esic[\s_-]?number|esic[\s_-]?num|esic[\s_-]?no|esic[\s_-]?id|esic[\s_-]?identifier|esic[\s_-]?code|esic[\s_-]?insurance[\s_-]?number|esic[\s_-]?insurance[\s_-]?id|esic[\s_-]?member[\s_-]?id|esic[\s_-]?member[\s_-]?number|esic[\s_-]?registration[\s_-]?number|esic[\s_-]?registration[\s_-]?id|esi|esi[\s_-]?number|esi[\s_-]?num|esi[\s_-]?no|esi[\s_-]?id|esi[\s_-]?identifier|esi[\s_-]?insurance[\s_-]?number|esi[\s_-]?member[\s_-]?id|esi[\s_-]?member[\s_-]?number|employee[\s_-]?state[\s_-]?insurance|employee[\s_-]?state[\s_-]?insurance[\s_-]?number|employee[\s_-]?state[\s_-]?insurance[\s_-]?id|employee[\s_-]?insurance[\s_-]?number|insured[\s_-]?person[\s_-]?number|insured[\s_-]?person[\s_-]?id|insurance[\s_-]?number[\s_-]?esic|insurance[\s_-]?id[\s_-]?esic)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - ESIC specific fallback; also home for the ambiguous "ip_number"/"ip_id" alias
				Regexp: regexp.MustCompile(`(?i)^.*(esic|esi[\s_-]?number|esic[\s_-]?member|employee[\s_-]?state[\s_-]?insurance|insured[\s_-]?person[\s_-]?number|insured[\s_-]?person[\s_-]?id|ip[\s_-]?number|ip[\s_-]?id).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_RationCard: {
			{
				// High confidence - Ration Card related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(ration[\s_-]?card|ration[\s_-]?card[\s_-]?number|ration[\s_-]?card[\s_-]?num|ration[\s_-]?card[\s_-]?no|ration[\s_-]?card[\s_-]?id|ration[\s_-]?card[\s_-]?identifier|ration[\s_-]?card[\s_-]?code|ration[\s_-]?number|ration[\s_-]?num|ration[\s_-]?no|ration[\s_-]?id|ration[\s_-]?identifier|ration[\s_-]?book|ration[\s_-]?book[\s_-]?number|ration[\s_-]?book[\s_-]?id|family[\s_-]?ration[\s_-]?card|family[\s_-]?ration[\s_-]?number|food[\s_-]?security[\s_-]?card|food[\s_-]?security[\s_-]?card[\s_-]?number|food[\s_-]?card|food[\s_-]?card[\s_-]?number|public[\s_-]?distribution[\s_-]?system[\s_-]?card|public[\s_-]?distribution[\s_-]?system[\s_-]?number|pds[\s_-]?card|pds[\s_-]?card[\s_-]?number|nfsa[\s_-]?card|nfsa[\s_-]?card[\s_-]?number|smart[\s_-]?ration[\s_-]?card|smart[\s_-]?ration[\s_-]?card[\s_-]?number|household[\s_-]?ration[\s_-]?card|household[\s_-]?ration[\s_-]?number|family[\s_-]?food[\s_-]?card)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - Ration Card specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(ration[\s_-]?card|family[\s_-]?ration[\s_-]?card|food[\s_-]?security[\s_-]?card|food[\s_-]?card|public[\s_-]?distribution[\s_-]?system[\s_-]?card|pds[\s_-]?card|nfsa[\s_-]?card|smart[\s_-]?ration[\s_-]?card).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_SEBIRegistration: {
			{
				// High confidence - SEBI Registration related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(sebi|sebi[\s_-]?registration|sebi[\s_-]?registration[\s_-]?number|sebi[\s_-]?registration[\s_-]?num|sebi[\s_-]?registration[\s_-]?no|sebi[\s_-]?registration[\s_-]?id|sebi[\s_-]?registration[\s_-]?identifier|sebi[\s_-]?registration[\s_-]?code|sebi[\s_-]?reg|sebi[\s_-]?reg[\s_-]?number|sebi[\s_-]?reg[\s_-]?no|sebi[\s_-]?reg[\s_-]?id|sebi[\s_-]?certificate|sebi[\s_-]?certificate[\s_-]?number|sebi[\s_-]?certificate[\s_-]?id|sebi[\s_-]?license|sebi[\s_-]?license[\s_-]?number|sebi[\s_-]?approval[\s_-]?number|sebi[\s_-]?approval[\s_-]?id|sebi[\s_-]?member[\s_-]?id|sebi[\s_-]?member[\s_-]?number|broker[\s_-]?sebi[\s_-]?registration|broker[\s_-]?sebi[\s_-]?registration[\s_-]?number|stock[\s_-]?broker[\s_-]?sebi[\s_-]?registration|investment[\s_-]?advisor[\s_-]?sebi[\s_-]?registration|investment[\s_-]?adviser[\s_-]?sebi[\s_-]?registration|merchant[\s_-]?banker[\s_-]?sebi[\s_-]?registration|portfolio[\s_-]?manager[\s_-]?sebi[\s_-]?registration|research[\s_-]?analyst[\s_-]?sebi[\s_-]?registration|mutual[\s_-]?fund[\s_-]?sebi[\s_-]?registration|depository[\s_-]?participant[\s_-]?sebi[\s_-]?registration)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - SEBI Registration specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(sebi[\s_-]?registration|sebi[\s_-]?reg|broker[\s_-]?sebi|investment[\s_-]?advisor[\s_-]?sebi|investment[\s_-]?adviser[\s_-]?sebi|merchant[\s_-]?banker[\s_-]?sebi|portfolio[\s_-]?manager[\s_-]?sebi|research[\s_-]?analyst[\s_-]?sebi|mutual[\s_-]?fund[\s_-]?sebi|depository[\s_-]?participant[\s_-]?sebi).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
		PIILabel_VehicleNumber: {
			{
				// High confidence - Vehicle Registration Number related column names (word-bounded)
				Regexp: regexp.MustCompile(`(?i)\b(vehicle[\s_-]?number|vehicle[\s_-]?no|vehicle[\s_-]?num|vehicle[\s_-]?registration|vehicle[\s_-]?registration[\s_-]?number|vehicle[\s_-]?registration[\s_-]?no|vehicle[\s_-]?registration[\s_-]?num|vehicle[\s_-]?registration[\s_-]?id|vehicle[\s_-]?registration[\s_-]?mark|vehicle[\s_-]?reg|vehicle[\s_-]?reg[\s_-]?number|vehicle[\s_-]?reg[\s_-]?no|vehicle[\s_-]?reg[\s_-]?num|registration[\s_-]?mark|registration[\s_-]?mark[\s_-]?number|registration[\s_-]?plate|registration[\s_-]?plate[\s_-]?number|number[\s_-]?plate|number[\s_-]?plate[\s_-]?number|license[\s_-]?plate|license[\s_-]?plate[\s_-]?number|licence[\s_-]?plate|licence[\s_-]?plate[\s_-]?number|vehicle[\s_-]?plate|vehicle[\s_-]?plate[\s_-]?number|plate[\s_-]?number|motor[\s_-]?vehicle[\s_-]?number|motor[\s_-]?vehicle[\s_-]?registration|motor[\s_-]?vehicle[\s_-]?registration[\s_-]?number|automobile[\s_-]?registration[\s_-]?number|car[\s_-]?registration[\s_-]?number|bike[\s_-]?registration[\s_-]?number|motorcycle[\s_-]?registration[\s_-]?number|truck[\s_-]?registration[\s_-]?number|bus[\s_-]?registration[\s_-]?number|commercial[\s_-]?vehicle[\s_-]?registration|commercial[\s_-]?vehicle[\s_-]?registration[\s_-]?number|transport[\s_-]?vehicle[\s_-]?registration|transport[\s_-]?vehicle[\s_-]?registration[\s_-]?number|vrn|vehicle[\s_-]?vrn)\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// Low confidence - Vehicle Registration Number specific fallback
				Regexp: regexp.MustCompile(`(?i)^.*(vehicle[\s_-]?registration|vehicle[\s_-]?number|vehicle[\s_-]?reg|registration[\s_-]?mark|registration[\s_-]?plate|number[\s_-]?plate|license[\s_-]?plate|licence[\s_-]?plate|vehicle[\s_-]?plate|motor[\s_-]?vehicle[\s_-]?registration|commercial[\s_-]?vehicle[\s_-]?registration|transport[\s_-]?vehicle[\s_-]?registration|vrn|vehicle[\s_-]?vrn).*$`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},
	}
	r.filterByRegion(r.region)
	return nil
}

// regexValueDetector is a detector which uses regexes to detect
// PIILabels for values.
//
// It uses some common regexes for some known value patterns.
type regexValueDetector struct {
	*baseRegexDetector
	region string
}

// NewRegexValueDetector returns a new regex value detector
func NewRegexValueDetector() Detector {
	return NewRegexValueDetectorForRegion("")
}

// NewRegexValueDetectorForRegion returns a new regex value detector
// that only loads regexes matching the given region.
// Use RegionIndia, or an empty string for all regions.
func NewRegexValueDetectorForRegion(region string) Detector {
	return &regexValueDetector{
		baseRegexDetector: &baseRegexDetector{},
		region:            region,
	}
}

// Init populates the map with PIILabel and list of regexes for
// known value patterns.
func (r *regexValueDetector) Init() error {
	r.m = map[PIILabel][]RegexWithWeight{
		PIILabel_Email: {
			{
				Regexp: regexp.MustCompile(`\b[\w][\w+.-]+(@|%40)[a-z\d-]+(\.[a-z\d-]+)*\.[a-z]+\b`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)([A-Za-z0-9!#$%&'*+\/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)`),
				Weight: 1.0,
			},
		},
		PIILabel_PANNumber: {
			{
				Regexp: regexp.MustCompile(`\b([A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt]{1}[A-Za-z]{1}[0-9]{4}[A-Za-z]{1})\b`),
				Weight: 0.85,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`\b([A-Za-z]{5}[0-9]{4}[A-Za-z]{1})\b`),
				Weight: 0.85,
				Region: RegionIndia,
			},
			// {
			// 	Regexp: regexp.MustCompile(`\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\w@#$%^?~-]{10})\b`),
			// 	Weight: 0.05,
			//        Region: RegionIndia,
			// },
		},
		PIILabel_AdharcardNumber: {
			{
				// Plain 12 digits
				Regexp: regexp.MustCompile(`\b\d{12}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				// With space or dash separators: 2345 6789 0123 or 2345-6789-0123
				Regexp: regexp.MustCompile(`\b\d{4}[- ]\d{4}[- ]\d{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				// Parentheses format: (2345) 6789 0123
				Regexp: regexp.MustCompile(`\(\d{4}\)\s\d{4}\s\d{4}`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				// Mixed separators: 2345.6789.0123
				Regexp: regexp.MustCompile(`\b\d{4}[.\s_-]\d{4}[.\s_-]\d{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
		},
		PIILabel_BankAccountNumber: {
			{
				// India: safe lengths - no collision with phone/aadhaar/card
				// includes 9-digit as Indian bank accounts use 9 digits
				// RequiresColumnContext to avoid collision with MICR (9-digit) and CIF (8-11 digit)
				Regexp:                regexp.MustCompile(`^(?:\d[\s\-]?){9,18}$`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_DematAccountNumber: {
			{
				// NSDL BO ID
				Regexp: regexp.MustCompile(`\bin\d{14}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
			{
				// CDSL BO ID
				Regexp: regexp.MustCompile(`\b(12|13|16|11|10)\d{14}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_ChequeNumber: {
			{
				// Indian cheque numbers are typically 6 digits.
				// Require column context to avoid matching OTPs, PINs, invoice IDs, etc.
				Regexp:                regexp.MustCompile(`^\d{6}$`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_CIFNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\bCIF\d{6,12}\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
			{
				Regexp:                regexp.MustCompile(`(?i)\b\d{8,11}\b`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_LoanAccountNumber: {
			{
				// Indian loan account numbers (bank specific)
				Regexp:                regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9\-_/]{8,25}[A-Za-z0-9]\b`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_InsurancePolicyNumber: {
			{
				// Indian insurance policy numbers (insurer specific)
				Regexp:                regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9\-_]{6,25}[A-Za-z0-9]\b`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_FASTagID: {
			{
				// FASTag identifiers are issuer-specific.
				Regexp:                regexp.MustCompile(`(?i)\b[A-Z0-9]{10,24}\b`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_UPIID: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[\w.\-]{2,}@(ybl|ibl|axl|okaxis|okhdfcbank|okicici|oksbi|paytm|ptsbi|pthdfc|ptaxis|ptyes|apl|rapl|yapl|waaxis|waicici|wahdfcbank|wasbi|yesg|yescred|yespop|superyes|ikwik|mvhdfc|fkaxis|indie|federal|fifederal|icici|axisb|hsbc|idbi|indianbank|allbank|kotak|kotak811|barodampay|pnb|unionbank|canara|bob|sbi|hdfcbank|icicibank|axisbank|idfcfirst|idfc|rbl|bandhan|yesbank|indus|indusind|au|aubank|equitas|ujjivan|airtel|freecharge|famapp|slice|cred|groww|jupiter|mobikwik|amazonpay|flipkart|phonepe|gpay|bhim|upi)\b`),
				Weight: 1.2,
				Region: RegionIndia,
			},
		},
		PIILabel_CVV: {
			{
				Regexp:                regexp.MustCompile(`^[0-9]{3,4}$`),
				Weight:                0.9,
				RequiresColumnContext: true,
			},
		},
		PIILabel_TAN: {
			{
				Regexp:                regexp.MustCompile(`(?i)\b[A-Z]{4}[0-9]{5}[A-Z]\b`),
				Weight:                0.9,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_CIN: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[LU][0-9]{5}(?:AN|AP|AR|AS|BR|CH|CG|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|PB|PY|RJ|SK|TN|TR|TS|UK|UP|WB)(?:18|19|20|21)[0-9]{2}[A-Z]{3}[0-9]{6}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_DrivingLicenceNumber: {
			{
				// Indian driving license — all state/UT codes including TG (new Telangana 2024), LD (Lakshadweep), TS (old Telangana still valid)
				Regexp: regexp.MustCompile(`(?i)^((?:ap|ar|as|br|cg|ch|dl|ga|gj|hp|hr|jh|jk|ka|kl|la|ld|mh|ml|mn|mp|mz|nl|od|pb|py|rj|sk|tg|tn|tr|ts|uk|up|wb|an|dd|dn)[\s_-]?[0-9]{2}[\s_-]?(?:19[89][0-9]|20[012][0-9])[\s_-]?[0-9]{7})$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// New Sarathi format: state(2) + district(2) + serial(11) = 15 chars
				Regexp:                regexp.MustCompile(`(?i)\b((?:ap|ar|as|br|cg|ch|dl|ga|gj|hp|hr|jh|jk|ka|kl|la|ld|mh|ml|mn|mp|mz|nl|od|pb|py|rj|sk|tg|tn|tr|ts|uk|up|wb|an|dd|dn)[\s_-]?[0-9]{2}[\s_-]?[0-9]{11})\b`),
				Weight:                0.9,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_Gender: {
			{
				Regexp: regexp.MustCompile(`(?i)^(male|female|girl|boy|other|prefer[\s-_]?not[\s-_]?to[\s-_]?say|prefer[\s-_]?not[\s-_]?to[\s-_]?disclose|not[\s-_]?specified|transgender|non[\s-_]?binary)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gender).*$`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^(m|f|n)$`),
				Weight: 0.3,
			},
		},

		PIILabel_Phone: {
			{
				// India mobile - bare 10 digit
				Regexp: regexp.MustCompile(`\b[6-9][0-9]{9}\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// India mobile - 0 prefix
				Regexp: regexp.MustCompile(`\b0[6-9][0-9]{9}\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// India mobile - 91 prefix
				Regexp:                regexp.MustCompile(`\b91[6-9][0-9]{9}\b`),
				Weight:                1.0,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
			{
				// India mobile - +91 prefix
				Regexp: regexp.MustCompile(`\+91[\s-]?[6-9][0-9]{4}[\s-]?[0-9]{5}`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_CreditCard: {
			{
				// 16-digit cards with separators (Visa, MC, RuPay, Discover)
				Regexp: regexp.MustCompile(`\b([234568]\d{3}[\s\-]*\d{4}[\s\-]*\d{4}[\s\-]*\d{4})\b`),
				Weight: 1.0,
			},
			{
				// 16-digit cards plain (no separator)
				Regexp: regexp.MustCompile(`\b[234568]\d{15}\b`),
				Weight: 1.0,
			},
			{
				// 15-digit Amex: 4-6-5 or 4-4-3 format or plain
				Regexp: regexp.MustCompile(`\b(3[47]\d{2}[\s\-]\d{4,6}[\s\-]\d{3,5})\b`),
				Weight: 1.0,
			},
			{
				// 15-digit Amex plain
				Regexp: regexp.MustCompile(`\b3[47]\d{13}\b`),
				Weight: 1.0,
			},
		},
		PIILabel_VoterID: {
			{
				Regexp:                regexp.MustCompile(`(?i)\b[A-Z]{3}\d{7}\b`),
				Weight:                0.8,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_IFSC: {
			{
				// IFSC: 4 letters + 0 + 6 alphanumeric
				Regexp: regexp.MustCompile(`(?i)^[A-Z]{4}0[A-Z0-9]{6}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_MICRCode: {
			{
				// MICR: 9-digit City(3)+Bank(3)+Branch(3). Column context required.
				Regexp:                regexp.MustCompile(`^\d{9}$`),
				Weight:                0.7,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_PassportNumber: {
			{
				// 1 letter + 7 digits
				Regexp:                regexp.MustCompile(`(?i)\b[A-Z][0-9]{7}\b`),
				Weight:                1.0,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
			{
				// 2 letters + 6 digits
				Regexp:                regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{6}\b`),
				Weight:                1.0,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_ABHANumber: {
			{
				// ABHA dashed format: 12-3456-7890-1234
				Regexp: regexp.MustCompile(`\b\d{2}-\d{4}-\d{4}-\d{4}\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// ABHA spaced format: 12 3456 7890 1234
				Regexp: regexp.MustCompile(`\b\d{2}\s\d{4}\s\d{4}\s\d{4}\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// ABHA plain 14 digits
				Regexp: regexp.MustCompile(`\b\d{14}\b`),
				Weight: 0.6,
				Region: RegionIndia,
			},
		},
		PIILabel_UAN: {
			{
				Regexp:                regexp.MustCompile(`\b[1-9][0-9]{11}\b`),
				Weight:                0.95,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_EPFMemberID: {
			{
				// Official EPF format: STATE(2)/OFFICE(3)/ESTABLISHMENT(7)/EXTENSION(3)/MEMBER(7) e.g. MH/BAN/0012345/000/0000123
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{2}/[A-Z]{3}/\d{7}/\d{3}/\d{7}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
			{
				// Compact format (without slashes): 22 characters e.g. MHBAN00123450000000123
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{2}[A-Z]{3}\d{7}\d{3}\d{7}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
			{
				// EPF / PF prefixed format e.g. EPF123456789012345, PF123456789012345
				Regexp: regexp.MustCompile(`(?i)\b(?:EPF|PF)[\s_-]?\d{15,22}\b`),
				Weight: 0.90,
				Region: RegionIndia,
			},
		},
		PIILabel_GSTIN: {
			{
				Regexp: regexp.MustCompile(
					`(?i)\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z][ZDC][0-9A-Z]\b`,
				),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_VehicleNumber: {
			{
				// Standard Registration
				Regexp: regexp.MustCompile(`(?i)\b(?:AN|AP|AR|AS|BR|CG|CH|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|PB|PY|RJ|SK|TN|TR|TS|UK|UP|WB)[ -]?[0-9]{2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				// Bharat (BH) Series
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{2}[ -]?BH[ -]?[0-9]{4}[ -]?[A-Z]{2}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				// Vintage (VA) Series
				Regexp: regexp.MustCompile(`(?i)\b(?:AN|AP|AR|AS|BR|CG|CH|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|PB|PY|RJ|SK|TN|TR|TS|UK|UP|WB)[ -]?VA[ -]?[A-Z]{2}[ -]?[0-9]{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				// Diplomatic Registration
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{3}[ -]?(?:CD|CC|UN)[ -]?[0-9]{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
		},

		PIILabel_IPAddress: {
			{
				Regexp: regexp.MustCompile(
					`(?:^|[^0-9])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?)(?:$|[^0-9])`,
				),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(
					`(?i)(?:^|[^0-9A-Fa-f:])((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|::ffff:\d{1,3}(?:\.\d{1,3}){3})(?:%[0-9A-Za-z._-]+)?(?:$|[^0-9A-Fa-f:])`,
				),
				Weight: 1.0,
			},
			// regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:))$`),
		},
		PIILabel_MacAddress: {
			{
				//Supports colon, dash and Cisco dotted notation
				Regexp: regexp.MustCompile(
					`(?i)\b[0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5}\b|\b[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}\b`,
				),
				Weight: 1.0,
			},
		},
		PIILabel_OAuthToken: {
			{
				// Google OAuth Access Token
				Regexp: regexp.MustCompile(`\bya29\.[a-zA-Z0-9_\-]{50,250}\b`),
				Weight: 0.95,
			},
			{
				// Google OAuth Refresh Token
				Regexp: regexp.MustCompile(`\b1//[a-zA-Z0-9_\-]{40,200}\b`),
				Weight: 0.95,
			},
			{
				// GitHub OAuth / Personal Access Tokens (gho_, ghp_, ghu_, ghr_)
				Regexp: regexp.MustCompile(`\bgh[opur]_[a-zA-Z0-9]{36,255}\b`),
				Weight: 0.95,
			},
			{
				// Slack OAuth Tokens (xoxp-, xoxb-, xoxa-, xoxr-)
				Regexp: regexp.MustCompile(`\bxox[pbar]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b`),
				Weight: 0.95,
			},
			{
				// JWT (JSON Web Token) - 3-part base64 header.payload.signature
				Regexp: regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-=]{10,}\.[a-zA-Z0-9_\-\.=]{3,}\b`),
				Weight: 0.90,
			},
		},
		PIILabel_Address: {
			{
				Regexp: regexp.MustCompile(`(?i)\b\d+\b.{4,60}\b(st|street|ave|avenue|road|rd|drive|dr)\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`\d{1,4} [a-zA-Z0-9]{1,20}( (street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd))\W?(\s|$)`),
				Weight: 0.8,
			},
		},
		PIILabel_ESIC: {
			{
				// ESIC: 17-digit format XX-XX-XXXXXX-XXX-XXXX
				Regexp: regexp.MustCompile(`\b\d{2}[-\s]\d{2}[-\s]\d{6}[-\s]\d{3}[-\s]\d{4}\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
			{
				// ESIC plain 17-digit format (no separators)
				Regexp: regexp.MustCompile(`\b\d{17}\b`),
				Weight: 0.6,
				Region: RegionIndia,
			},
		},
		PIILabel_RationCard: {
			{
				// Ration card: state code + alphanumeric
				Regexp: regexp.MustCompile(`(?i)^(AP|AR|AS|BR|CG|CH|DL|GA|GJ|HP|HR|JH|JK|KA|KL|LA|MH|ML|MN|MP|MZ|NL|OD|PB|PY|RJ|SK|TN|TR|TS|UK|UP|WB|AN|DD|DN)[-/]?\d{10,15}$`),
				Weight: 0.7,
				Region: RegionIndia,
			},
		},
		PIILabel_SEBIRegistration: {
			{
				// SEBI: INZ/INH/INP + 9 digits e.g. INZ000123456
				Regexp: regexp.MustCompile(`(?i)\b(INZ|INH|INP|INR|INA|INM|INQ)\d{9}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_BirthDate: {
			{
				// Common date formats: DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, DD.MM.YYYY
				Regexp:                regexp.MustCompile(`\b(0[1-9]|[12]\d|3[01])[\/\-\.](0[1-9]|1[0-2])[\/\-\.](19|20)\d{2}\b|\b(19|20)\d{2}[\/\-\.](0[1-9]|1[0-2])[\/\-\.](0[1-9]|[12]\d|3[01])\b`),
				Weight:                1.0,
				RequiresColumnContext: true,
			},
		},
		PIILabel_Location: {
			{
				// Latitude/Longitude coordinate pair: 18.9220, 72.8347
				Regexp: regexp.MustCompile(`^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$`),
				Weight: 0.9,
			},
		},
	}
	r.filterByRegion(r.region)
	return nil
}
