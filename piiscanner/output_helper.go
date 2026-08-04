package piiscanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
	"github.com/olekukonko/tablewriter"
)

func PrintTerminalOutput(i *DatabasePIIScanOutput, cnf Config) {
	if !i.HasFindings() {
		fmt.Println("> No PII data found in database")
		return
	}

	if cnf.PrintSummaryOnly {
		printTerminalOutputSimple(i)
	} else {
		printTerminalOutputTable(i, cnf)
	}

}

func printTerminalOutputTable(i *DatabasePIIScanOutput, cnf Config) {
	GenerateTabularOutput(os.Stdout, i, cnf, "")
}

func CreateTabularOutputfile(i *DatabasePIIScanOutput, cnf Config) {
	if !i.HasFindings() {
		return
	}

	highConfidenceFile, err := os.Create("kshield_pii_highconfidence.log")
	if err != nil {
		fmt.Println("Error creating high confidence log file: ", text.FgRed.Sprint(err))
		return
	}
	defer highConfidenceFile.Close()

	GenerateTabularOutput(highConfidenceFile, i, cnf, "High")

	HighConfidenceFilePath, _ := filepath.Abs(highConfidenceFile.Name())
	fmt.Println("> High confidence log file created at: [ " + HighConfidenceFilePath + " ]")

	// Low/medium confidence is suppressed by default to reduce noise.
	// Pass --print-all to also write the low-confidence log.
	if !cnf.printAllResults {
		return
	}

	lowConfidenceFile, err := os.Create("kshield_pii_lowconfidence.log")
	if err != nil {
		fmt.Println("Error creating low confidence log file: ", text.FgRed.Sprint(err))
		return
	}
	defer lowConfidenceFile.Close()

	GenerateTabularOutput(lowConfidenceFile, i, cnf, "Medium|Low")

	lowConfidenceFilePath, _ := filepath.Abs(lowConfidenceFile.Name())
	fmt.Println("> Low confidence log file created at: [ " + lowConfidenceFilePath + " ]")
}

func GenerateTabularOutput(w io.Writer, i *DatabasePIIScanOutput, cnf Config, filePrint string) {
	columnTable := tablewriter.NewWriter(w)
	headers := []string{"Table", "Column", "Label", "Confidence"}
	columnTable.SetHeader(headers)

	valueTable := tablewriter.NewWriter(w)
	headers = []string{"Table", "Column", "Label", "Confidence", "Detector", "Matched"}
	valueTable.SetHeader(headers)

	var renderValueTable, renderColumnTable bool
	tablesWithPIIData := utils.NewSet[string]()
	tableShowingInTopTable := utils.NewSet[string]()
	for tablename, columns := range i.Data {
		for columnName, piidatas := range columns {
			for _, piidata := range piidatas {
				tablesWithPIIData.Add(tablename)
				if filePrint == "" && !cnf.printAllResults && piidata.Confidence != "High" {
					continue
				} else if filePrint != "" && !strings.Contains(filePrint, piidata.Confidence) {
					continue
				}

				data := []string{tablename, columnName, string(piidata.Label), piidata.Confidence + " " + piidata.ConfidenceIcon}

				currentTable := columnTable
				if piidata.DetectorType == DetectorType_ValueDetector {
					data = append(data, piidata.DetectorName, fmt.Sprintf("%d/%d", piidata.MatchedCount, piidata.ScanedValueCount))
					currentTable = valueTable
				}

				currentTable.Append(data)
				renderColumnTable = renderColumnTable || piidata.DetectorType == DetectorType_ColumnDetector
				renderValueTable = renderValueTable || piidata.DetectorType == DetectorType_ValueDetector

				tableShowingInTopTable.Add(tablename)

				if filePrint == "" && !cnf.printAllResults {
					continue
				}
			}
		}
	}

	if renderValueTable {
		msg := "Data Scan Report"
		if filePrint == "" {
			msg = text.Bold.Sprint(msg)
		}
		fmt.Fprintln(w, msg)
		valueTable.SetAutoMergeCellsByColumnIndex([]int{0, 1})
		valueTable.SetRowLine(true)
		valueTable.SetAlignment(tablewriter.ALIGN_LEFT)
		valueTable.SetAutoWrapText(false)
		valueTable.Render()
	}

	if renderColumnTable {
		msg := "Meta Scan Report"
		if filePrint == "" {
			msg = text.Bold.Sprint(msg)
		}

		fmt.Fprintln(w, msg)
		columnTable.SetAutoMergeCellsByColumnIndex([]int{0, 1})
		columnTable.SetRowLine(true)
		columnTable.SetAlignment(tablewriter.ALIGN_LEFT)
		columnTable.SetAutoWrapText(false)
		columnTable.Render()
	}

	if filePrint != "" {
		return
	}

	switch {
	case tableShowingInTopTable.Len() == 0 && tablesWithPIIData.Len() == 0:
		fmt.Fprintln(w, "> No PII data found in database")

	case tableShowingInTopTable.Len() == 0 && tablesWithPIIData.Len() != 0:
		fmt.Fprintln(w, "> No high-confidence PII entities were found. Some low/medium-confidence entities were identified in the following tables:")
		fmt.Fprintln(w, text.FgHiRed.Sprint(utils.AraryToHumanReadableString(tablesWithPIIData.Slice())))
		fmt.Fprintln(w, "Re-run with --print-all to include low/medium confidence results in the terminal, log files, and HTML report.")

	case tableShowingInTopTable.Len() != 0 && tablesWithPIIData.Len() != 0 && tableShowingInTopTable.Len() != tablesWithPIIData.Len():
		fmt.Fprintln(w, "> Showing high-confidence entities only. Some low/medium-confidence entities were also identified in the following tables:")
		fmt.Fprintln(w, text.FgHiRed.Sprint(utils.AraryToHumanReadableString(tablesWithPIIData.Slice())))
		fmt.Fprintln(w, "Re-run with --print-all to include low/medium confidence results in the terminal, log files, and HTML report.")
	}

	fmt.Fprintln(w, "")
}

func printTerminalOutputSimple(i *DatabasePIIScanOutput) {
	if !i.HasFindings() {
		fmt.Println("> No PII data found in database")
		return
	}

	// var renderValueTable, renderColumnTable bool
	m := map[string] /* table name */ map[string] /* confidence */ map[string] /* detector */ []string{}
	for tablename, columns := range i.Data {
		m[tablename] = map[string]map[string][]string{}
		for columnName, piidatas := range columns {
			for _, piidata := range piidatas {
				if _, ok := m[tablename][piidata.Confidence]; !ok {
					m[tablename][piidata.Confidence] = map[string][]string{}
				}

				if _, ok := m[tablename][piidata.Confidence][string(piidata.DetectorType)]; !ok {
					m[tablename][piidata.Confidence][string(piidata.DetectorType)] = []string{}
				}

				m[tablename][piidata.Confidence][string(piidata.DetectorType)] = append(m[tablename][piidata.Confidence][string(piidata.DetectorType)],
					fmt.Sprintf("%s as %s", columnName, piidata.Label))
			}
		}
	}

	fmt.Println()
	headerPrinted := false
	// print all tables with high confidence
	for tablename, confidences := range m {
		if _, ok := confidences["High"]; ok {
			if !headerPrinted {
				fmt.Println("Tables with high confidence PII data:")
				headerPrinted = true
			}
			fmt.Printf("%s \n", text.FgHiRed.Sprint(tablename))
			for detector, columns := range confidences["High"] {
				// fmt.Printf("-> %s (%d column): \n    - %s\n", detector, len(columns), strings.Join(columns, "\n    - "))
				fmt.Printf("-> %s (%d column): %s\n", detector, len(columns), utils.AraryToHumanReadableString(columns))
			}
		}
	}
	fmt.Println()

	fmt.Println("Showing high-confidence summary only. Re-run with --print-all (without --print-summary) for low/medium confidence details.")
}
