package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

var columnContextEntities = map[string]string{
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
	"ABHANumber":            "abha_number",
}

func main() {
	file, err := os.Open("india_benchmark.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	reader := csv.NewReader(file)

	valDetector := piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia)
	if err := valDetector.Init(); err != nil {
		log.Fatal(err)
	}

	scanner := piiscanner.NewPiiScanner()
	scanner.AddColumnDetector(piiscanner.NewRegexColumnDetectorForRegion(piiscanner.RegionIndia))
	scanner.AddValueDetector(piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia))
	if err := scanner.Init(); err != nil {
		log.Fatal(err)
	}

	total, correct := 0, 0
	perLabelTotal := make(map[string]int)
	perLabelCorrect := make(map[string]int)
	fpByLabel := make(map[string]int)
	confusion := make(map[string]map[string]int)

	// skip header
	if _, err := reader.Read(); err != nil {
		log.Fatal(err)
	}

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		value, expected := record[0], record[1]
		total++
		perLabelTotal[expected]++

		predicted := "NEG"

		if col, ok := columnContextEntities[expected]; ok {
			label, err := scanner.Detect(context.Background(), col, value)
			if err != nil {
				log.Fatal(err)
			}
			if label != "" {
				predicted = string(label)
			}
		} else {
			labels, err := valDetector.Detect(context.Background(), value, nil)
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

	labels := make(map[string]bool)

	for label := range perLabelTotal {
		labels[label] = true
	}

	for label := range fpByLabel {
		labels[label] = true
	}

	var orderedLabels []string
	for label := range labels {
		orderedLabels = append(orderedLabels, label)
	}

	sort.Strings(orderedLabels)

	for _, label := range orderedLabels {
		fmt.Println(label)
	}

	var (
		totalTP int
		totalFP int
		totalFN int

		macroPrecision float64
		macroRecall    float64
		macroF1        float64

		entityCount int
	)

	fmt.Println("\n========== DETAILED METRICS ==========")

	fmt.Printf("%-28s %6s %6s %6s %6s %10s %10s %10s %10s\n",
		"Entity",
		"TP",
		"FP",
		"FN",
		"TN",
		"Precision",
		"Recall",
		"F1",
		"Accuracy")

	for _, label := range orderedLabels {

		if label == "NEG" {
			continue
		}

		tp := confusion[label][label]

		fp := 0
		fn := 0

		for _, other := range orderedLabels {

			if other == label {
				continue
			}

			fp += confusion[other][label]
			fn += confusion[label][other]
		}

		tn := total - tp - fp - fn

		precision := 0.0
		recall := 0.0
		f1 := 0.0
		accuracy := 0.0

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
			label,
			tp,
			fp,
			fn,
			tn,
			precision*100,
			recall*100,
			f1*100,
			accuracy*100)
	}

	fmt.Println("\n========== OVERALL METRICS ==========")

	macroPrecision /= float64(entityCount)
	macroRecall /= float64(entityCount)
	macroF1 /= float64(entityCount)

	microPrecision := float64(totalTP) / float64(totalTP+totalFP)
	microRecall := float64(totalTP) / float64(totalTP+totalFN)

	microF1 := 0.0
	if microPrecision+microRecall > 0 {
		microF1 = 2 * microPrecision * microRecall /
			(microPrecision + microRecall)
	}

	fmt.Printf("Macro Precision : %.2f%%\n", macroPrecision*100)
	fmt.Printf("Macro Recall    : %.2f%%\n", macroRecall*100)
	fmt.Printf("Macro F1 Score  : %.2f%%\n", macroF1*100)

	fmt.Println()

	fmt.Printf("Micro Precision : %.2f%%\n", microPrecision*100)
	fmt.Printf("Micro Recall    : %.2f%%\n", microRecall*100)
	fmt.Printf("Micro F1 Score  : %.2f%%\n", microF1*100)
}
