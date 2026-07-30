package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

var columnContextEntitiesSpacyV2 = map[string]string{
	"BankAccountNumber":     "account_number",
	"ChequeNumber":          "cheque_number",
	"CIFNumber":             "cif_number",
	"LoanAccountNumber":     "loan_account_number",
	"InsurancePolicyNumber": "policy_number",
	"FASTagID":              "fastag_id",
	"CVV":                   "cvv",
	"UAN":                   "uan",
	"RationCard":            "ration_card",
	"BirthDate":             "date_of_birth",
	"Location":              "latitude",
	// Spacy entities — column context only
	"Name":    "first_name",
	"Address": "address",
}

// Column keywords that trigger spacy for Name and Address
var spacyNameColumns = map[string]bool{
	"name": true, "first_name": true, "last_name": true,
	"full_name": true, "person_name": true, "customer_name": true,
	"employee_name": true, "contact_name": true, "fname": true, "lname": true,
}

var spacyAddressColumns = map[string]bool{
	"address": true, "street": true, "city": true, "locality": true,
	"residence": true, "location_address": true, "home_address": true,
	"office_address": true, "billing_address": true, "shipping_address": true,
}

func isSpacyColumn(col string) bool {
	col = strings.ToLower(col)
	return spacyNameColumns[col] || spacyAddressColumns[col]
}

func main() {
	totalStart := time.Now()

	file, err := os.Open("india_benchmark.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	reader := csv.NewReader(file)

	// Init regex value detector
	fmt.Println("Initializing regex detector...")
	regexStart := time.Now()
	valDetector := piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia)
	if err := valDetector.Init(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Regex detector initialized in %v\n", time.Since(regexStart))

	scanner := piiscanner.NewPiiScanner()
	scanner.AddColumnDetector(piiscanner.NewRegexColumnDetectorForRegion(piiscanner.RegionIndia))
	scanner.AddValueDetector(piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia))
	if err := scanner.Init(); err != nil {
		log.Fatal(err)
	}

	// Init spacy detector
	fmt.Println("Initializing spacy detector (loading en_core_web_lg model)...")
	spacyStart := time.Now()
	spacyDet := piiscanner.NewSpacyDetector().WithWorkDirs([]string{
		"../../python",
		"../python",
		"python",
	})
	spacyErr := spacyDet.Init()
	spacyLoadTime := time.Since(spacyStart)
	if spacyErr != nil {
		fmt.Printf("WARNING: Spacy detector failed to initialize: %v\n", spacyErr)
		fmt.Println("Running without spacy — Name and Address value detection disabled")
	} else {
		fmt.Printf("Spacy detector initialized in %v\n", spacyLoadTime)
	}

	total, correct := 0, 0
	perLabelTotal := make(map[string]int)
	perLabelCorrect := make(map[string]int)
	fpByLabel := make(map[string]int)
	confusion := make(map[string]map[string]int)

	var regexDuration time.Duration
	var spacyDuration time.Duration
	spacyCalls := 0
	spacySkipped := 0

	// skip header
	if _, err := reader.Read(); err != nil {
		log.Fatal(err)
	}

	scanStart := time.Now()

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		value, expected := record[0], record[1]
		total++
		perLabelTotal[expected]++

		predicted := "NEG"

		if col, ok := columnContextEntitiesSpacyV2[expected]; ok {
			// Context-dependent entities — use scanner with column name
			t := time.Now()
			label, err := scanner.Detect(context.Background(), col, value)
			regexDuration += time.Since(t)
			if err != nil {
				log.Fatal(err)
			}
			if label != "" {
				predicted = string(label)
			}

			// For Name/Address — only call spacy if column context matches
			if predicted == "NEG" && spacyErr == nil && (expected == "Name" || expected == "Address") {
				if isSpacyColumn(col) {
					t = time.Now()
					spacyLabels, err := spacyDet.Detect(context.Background(), value, nil)
					spacyDuration += time.Since(t)
					spacyCalls++
					if err == nil && len(spacyLabels) > 0 {
						sort.Slice(spacyLabels, func(i, j int) bool {
							return spacyLabels[i].Weight > spacyLabels[j].Weight
						})
						predicted = string(spacyLabels[0].PIILabel)
					}
				} else {
					spacySkipped++
				}
			}
		} else {
			// Run regex value detector
			t := time.Now()
			labels, err := valDetector.Detect(context.Background(), value, nil)
			regexDuration += time.Since(t)
			if err != nil {
				log.Fatal(err)
			}

			if len(labels) > 0 {
				sort.Slice(labels, func(i, j int) bool {
					return labels[i].Weight > labels[j].Weight
				})
				predicted = string(labels[0].PIILabel)
			}
		}

		if confusion[expected] == nil {
			confusion[expected] = make(map[string]int)
		}
		confusion[expected][predicted]++

		if predicted == expected {
			correct++
			perLabelCorrect[expected]++
		} else if expected == "NEG" && predicted != "NEG" {
			fpByLabel[predicted]++
		}
	}

	scanDuration := time.Since(scanStart)
	totalDuration := time.Since(totalStart)

	// ─── Timing Report ───────────────────────────────────────────
	fmt.Println("\n========== TIMING ==========")
	fmt.Printf("Spacy model load time  : %v\n", spacyLoadTime)
	fmt.Printf("Total scan time        : %v\n", scanDuration)
	fmt.Printf("  Regex detection      : %v\n", regexDuration)
	fmt.Printf("  Spacy detection      : %v (%d calls)\n", spacyDuration, spacyCalls)
	fmt.Printf("  Spacy skipped        : %d rows (no column context)\n", spacySkipped)
	fmt.Printf("Total time (all)       : %v\n", totalDuration)
	fmt.Printf("Rows processed         : %d\n", total)
	if total > 0 {
		fmt.Printf("Avg time per row       : %v\n", scanDuration/time.Duration(total))
	}
	if spacyCalls > 0 {
		fmt.Printf("Avg spacy time per call: %v\n", spacyDuration/time.Duration(spacyCalls))
	}

	// ─── Results ─────────────────────────────────────────────────
	fmt.Println("\n========== NEG BREAKDOWN ==========")
	for label, count := range fpByLabel {
		fmt.Printf("%-30s %d\n", label, count)
	}

	fmt.Println("\n========== RESULTS ==========")
	for label, tot := range perLabelTotal {
		fmt.Printf("%-30s %d/%d\n", label, perLabelCorrect[label], tot)
	}
	fmt.Println("-----------------------------")
	fmt.Printf("Overall Accuracy: %.2f%%\n", float64(correct)/float64(total)*100)

	fmt.Println("\n========== LABELS ==========")
	labelSet := make(map[string]bool)
	for label := range perLabelTotal {
		labelSet[label] = true
	}
	for label := range fpByLabel {
		labelSet[label] = true
	}
	var orderedLabels []string
	for label := range labelSet {
		orderedLabels = append(orderedLabels, label)
	}
	sort.Strings(orderedLabels)
	for _, label := range orderedLabels {
		fmt.Println(label)
	}

	var (
		totalTP        int
		totalFP        int
		totalFN        int
		macroPrecision float64
		macroRecall    float64
		macroF1        float64
		entityCount    int
	)

	fmt.Println("\n========== DETAILED METRICS ==========")
	fmt.Printf("%-28s %6s %6s %6s %6s %10s %10s %10s %10s\n",
		"Entity", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "Accuracy")

	for _, label := range orderedLabels {
		if label == "NEG" {
			continue
		}
		tp := confusion[label][label]
		fp, fn := 0, 0
		for _, other := range orderedLabels {
			if other == label {
				continue
			}
			fp += confusion[other][label]
			fn += confusion[label][other]
		}
		tn := total - tp - fp - fn

		precision, recall, f1, accuracy := 0.0, 0.0, 0.0, 0.0
		if tp+fp > 0 {
			precision = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			recall = float64(tp) / float64(tp+fn)
		}
		if precision+recall > 0 {
			f1 = 2 * precision * recall / (precision + recall)
		}
		if tp+tn+fp+fn > 0 {
			accuracy = float64(tp+tn) / float64(tp+tn+fp+fn)
		}

		totalTP += tp
		totalFP += fp
		totalFN += fn
		macroPrecision += precision
		macroRecall += recall
		macroF1 += f1
		entityCount++

		fmt.Printf("%-28s %6d %6d %6d %6d %9.2f%% %9.2f%% %9.2f%% %9.2f%%\n",
			label, tp, fp, fn, tn,
			precision*100, recall*100, f1*100, accuracy*100)
	}

	fmt.Println("\n========== OVERALL METRICS ==========")
	macroPrecision /= float64(entityCount)
	macroRecall /= float64(entityCount)
	macroF1 /= float64(entityCount)

	microPrecision := float64(totalTP) / float64(totalTP+totalFP)
	microRecall := float64(totalTP) / float64(totalTP+totalFN)
	microF1 := 0.0
	if microPrecision+microRecall > 0 {
		microF1 = 2 * microPrecision * microRecall / (microPrecision + microRecall)
	}

	fmt.Printf("Macro Precision : %.2f%%\n", macroPrecision*100)
	fmt.Printf("Macro Recall    : %.2f%%\n", macroRecall*100)
	fmt.Printf("Macro F1 Score  : %.2f%%\n", macroF1*100)
	fmt.Println()
	fmt.Printf("Micro Precision : %.2f%%\n", microPrecision*100)
	fmt.Printf("Micro Recall    : %.2f%%\n", microRecall*100)
	fmt.Printf("Micro F1 Score  : %.2f%%\n", microF1*100)
}
