package piiscanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	cons "github.com/klouddb/dpdpa_pii_db_scanner/pkg/const"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/postgresdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
	"github.com/schollz/progressbar/v3"
)

var yesToAll bool

type Config struct {
	runOption RunOption
	// AutoDetect is true when the caller didn't request a fixed scan mode
	// (--piiscanner was left empty). When true, runOption is RunOption_Unset
	// and the real per-table mode (DataScan vs DeepScan) is picked later, in
	// piiTableScanner.processTable, based on that table's row count.
	AutoDetect bool

	useSpacy     bool
	excludeTable utils.Set[string]
	includeTable []string

	Database string
	Schema   string

	printAllResults  bool
	spacyOnly        bool
	PrintSummaryOnly bool
}

func NewConfig(pgConfig *postgresdb.Postgres, runOption, excludeTable, includeTable, database, schema string,
	printAllResults, spacyOnly, printSummaryOnly bool) (*Config, error) {
	if printAllResults && printSummaryOnly {
		return nil, fmt.Errorf("--print-all and --print-summary are not allowed together")
	}

	if pgConfig == nil {
		return nil, errors.New(cons.Err_PostgresConfig_Missing)
	}

	var useSpacy bool
	if runOption == RunOption_SpacyScan_String {
		useSpacy = true
		runOption = RunOption_DataScan_String
		printAllResults = true
	}

	if spacyOnly {
		// incase of spacy only we will run data scan only and that also with spacy
		// so if there run option is available then it will create confusion for users
		// that which part is getting priority from run option and spacy only.
		// so in that case we will return error
		if runOption != "" {
			return nil, fmt.Errorf("run option is not allowed with spacy only")
		}

		runOption = RunOption_DataScan_String
		useSpacy = true

		// incase of only spacy we will get all results with 0.3 confidence value
		// default terminal output prints only results with High confidence value which is > 0.7
		// so in case of spacy only we will print all results
		printAllResults = true
	}

	autoDetect := runOption == ""

	r := RunOption_Unset
	if !autoDetect {
		var ok bool
		r, ok = RunOptionMap[runOption]
		if !ok {
			return nil, fmt.Errorf("invalid run option %s, valid options are %s", runOption, strings.Join(RunOptionSlice(), ", "))
		}
	}

	if database == "" {
		database = pgConfig.DBName
	}

	out := &Config{
		runOption:        r,
		AutoDetect:       autoDetect,
		useSpacy:         useSpacy,
		Database:         database,
		Schema:           schema,
		printAllResults:  printAllResults,
		spacyOnly:        spacyOnly,
		PrintSummaryOnly: printSummaryOnly,
	}

	if excludeTable != "" {
		out.excludeTable = utils.NewSetFromSlice(utils.TrimSpaceArray(strings.Split(excludeTable, ",")))
	}

	if includeTable != "" {
		out.includeTable = utils.TrimSpaceArray(strings.Split(includeTable, ","))
	}

	return out, nil
}

type DBHelper interface {
	GetAllTables(ctx context.Context, store *sql.DB) ([]string, error)
	UpdateTableName(table string) string
}

type postgresDBHelper struct {
	schema string
}

func NewPostgresDBHelper(schema string) DBHelper {
	if schema == "" {
		schema = "public"
	}
	return &postgresDBHelper{schema: schema}
}

func (p *postgresDBHelper) GetAllTables(ctx context.Context, store *sql.DB) ([]string, error) {
	// check if schema exists
	exists, err := utils.SchemaExists(ctx, store, p.schema)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("schema %s does not exist", p.schema)
	}

	return utils.GetListFromQuery(ctx, store, "SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema = '"+p.schema+"'")
}

func (p *postgresDBHelper) UpdateTableName(table string) string {
	return fmt.Sprintf("\"%s\".\"%s\"", p.schema, table)
}

type databasePiiScanner struct {
	h                DBHelper
	store            *sql.DB
	tableScanManager *TableScanManager

	numOfRunners int

	cnf *Config

	spinner *scanningSpinner
}

func NewDatabasePiiScanner(h DBHelper, store *sql.DB, cnf *Config) *databasePiiScanner {
	return &databasePiiScanner{
		h: h, store: store,
		numOfRunners: runtime.NumCPU(),
		cnf:          cnf,
	}
}

func (d *databasePiiScanner) Close() {
	if d.spinner != nil {
		d.spinner.Stop()
	}
}

func (d *databasePiiScanner) pauseSpinner() {
	if d.spinner != nil {
		d.spinner.Pause()
	}
}

func (d *databasePiiScanner) resumeSpinner() {
	if d.spinner != nil {
		d.spinner.Resume()
	}
}

func (d *databasePiiScanner) DetectorFactory() []Detector {
	detectors := []Detector{}

	if !d.cnf.spacyOnly {
		detectors = append(detectors, NewRegexValueDetector())
	}

	if d.cnf.useSpacy {
		detectors = append(detectors, NewSpacyDetector().WithWorkDirs([]string{"python", "/etc/klouddbshield/python", "../../python"}))
	}

	return detectors
}

func (d *databasePiiScanner) GetTables(ctx context.Context) ([]string, error) {
	if len(d.cnf.includeTable) != 0 {
		return d.cnf.includeTable, nil
	}

	tables, err := d.h.GetAllTables(ctx, d.store)
	if err != nil {
		return nil, fmt.Errorf("error getting tables: %v", err)
	}

	return tables, nil
}

type scanningSpinner struct {
	mu        sync.Mutex
	paused    bool
	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

func startScanningSpinner(delay time.Duration) *scanningSpinner {
	s := &scanningSpinner{
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	go func() {
		defer close(s.stopped)

		select {
		case <-s.done:
			return
		case <-time.After(delay):
		}

		frames := []string{"", ".", ". .", ". . ."}
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		i := 0
		for {
			select {
			case <-s.done:
				s.mu.Lock()
				fmt.Print("\r" + strings.Repeat(" ", 20) + "\r")
				s.mu.Unlock()
				return
			case <-ticker.C:
				s.mu.Lock()
				if !s.paused {
					fmt.Printf("\r> Scanning %-8s", frames[i%len(frames)])
					i++
				}
				s.mu.Unlock()
			}
		}
	}()

	return s
}

func (s *scanningSpinner) Pause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.paused {
		s.paused = true
		fmt.Print("\r" + strings.Repeat(" ", 20) + "\r")
	}
}

func (s *scanningSpinner) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused = false
}

func (s *scanningSpinner) Stop() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	<-s.stopped
}

func (d *databasePiiScanner) Scan(ctx context.Context) error {

	if d.cnf.runOption == RunOption_DeepScan {
		fmt.Println(text.FgCyan.Sprint("For huge databases, scanning all rows may take a considerable amount of time. To speed up"))
		fmt.Println(text.FgCyan.Sprint("the process, consider using the 'datascan' option, which will scan only"))
		fmt.Println(text.FgCyan.Sprint("10,000 rows per table"))
		fmt.Println()
	}

	tables, err := d.GetTables(ctx)
	if err != nil {
		return err
	}

	if len(tables) == 0 {
		fmt.Println("> No tables found in database")
		return nil
	}

	fmt.Println("> Found", len(tables), "tables")

	d.tableScanManager = NewTableScanManager().WithColumnDetector(NewRegexColumnDetector())
	if d.cnf.runOption != RunOption_MetaScan {
		d.tableScanManager.WithDetectorFactory(d.DetectorFactory)
	}

	initFunction := sync.OnceValue(func() error {
		err := d.tableScanManager.Start(ctx, d.numOfRunners)
		if err != nil {
			return err
		}

		fmt.Println("> Started table scan manager with", d.numOfRunners, "runners")
		d.spinner = startScanningSpinner(3 * time.Second)
		return nil
	})

	for _, table := range tables {
		if d.cnf.excludeTable != nil && d.cnf.excludeTable.Contains(table) {
			continue
		}

		err := initFunction()
		if err != nil {
			return fmt.Errorf("error starting table scan manager: %v", err)
		}

		// fmt.Println("> Processing table", table)
		s := NewPiiTableScanner(d.h.UpdateTableName(table), d.store, d.tableScanManager, d.cnf.runOption, d.cnf.AutoDetect, d.cnf.useSpacy, d.pauseSpinner, d.resumeSpinner)
		if err := s.processTable(ctx); err != nil {
			return fmt.Errorf("error processing table %s: %v", table, err)
		}
		// fmt.Println("> Done processing table", table)
	}
	return nil
}

type DatabasePIIScanOutput struct {
	ScanType        string
	SupportedLevels []string
	Data            map[string]TableDetailOutput
}
type TableDetailOutput map[string][]PIIDataWithWeightString

func (o *DatabasePIIScanOutput) HasFindings() bool {
	if o == nil {
		return false
	}
	for _, columns := range o.Data {
		for _, piidatas := range columns {
			if len(piidatas) > 0 {
				return true
			}
		}
	}
	return false
}

type PIIDataWithWeightString struct {
	Label            PIILabel
	Confidence       string
	ConfidenceIcon   string
	Weight           float64
	DetectorType     DetectorType
	DetectorName     string
	ScanedValueCount int
	MatchedCount     int
}

func NewPIIDataWithWeightString(label PIILabel, Weight float64, detectorType DetectorType, detectorName string) *PIIDataWithWeightString {
	confidence, icon := getConfidenceLabel(Weight)
	return &PIIDataWithWeightString{
		Label:          label,
		Confidence:     confidence,
		ConfidenceIcon: icon,
		Weight:         Weight,
		DetectorType:   detectorType,
		DetectorName:   detectorName,
	}
}

func (p *PIIDataWithWeightString) SetScanedValueAndMatchCount(matchCount, scanedValueCount int) {
	p.ScanedValueCount = scanedValueCount
	p.MatchedCount = matchCount
}

func (d *databasePiiScanner) GetResults() (*DatabasePIIScanOutput, error) {
	if d.tableScanManager == nil {
		// this handles the case when no table is scanned
		return nil, nil
	}

	data, err := d.tableScanManager.Output()
	if d.spinner != nil {
		d.spinner.Stop()
	}
	if err != nil {
		return nil, err
	}

	scanType := RunOptionTitleMap[d.cnf.runOption]
	if d.cnf.AutoDetect {
		scanType = AutoScanTitle
	}
	if d.cnf.useSpacy {
		scanType = RunOption_SpacyScan_Title
	}

	output := &DatabasePIIScanOutput{
		ScanType:        scanType,
		SupportedLevels: []string{"High", "Medium", "Low"},
		Data:            make(map[string]TableDetailOutput),
	}

	for _, table := range data {
		output.Data[table.TableName] = make(map[string][]PIIDataWithWeightString)
		for columnName, piiMap := range table.PiiDataMap {
			output.Data[table.TableName][columnName] = []PIIDataWithWeightString{}

			for detector, piiData := range piiMap.ColumnMap {
				for label, pii := range piiData {
					piiDataWithWeight := NewPIIDataWithWeightString(label, pii.Weight, DetectorType_ColumnDetector, detector)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			count := d.tableScanManager.valueCount[table.TableName][columnName]
			for detector, piiData := range piiMap.ValueMap {
				for label, pii := range piiData {
					var finalWeight float64
					if count != 0 {
						finalWeight = pii.Weight / float64(count)
					}
					if PiiEntitiesForWeightMergeLogic.Contains(label) {
						columnWeight := piiMap.ColumnMap["regex"][label].Weight
						if columnWeight >= 0.4 {
							finalWeight = (columnWeight + finalWeight) / 2
						}
					}

					piiDataWithWeight := NewPIIDataWithWeightString(label, finalWeight, DetectorType_ValueDetector, detector)
					piiDataWithWeight.SetScanedValueAndMatchCount(pii.Count, count)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			sort.Slice(output.Data[table.TableName][columnName], func(i, j int) bool {

				return OrderMap[string(output.Data[table.TableName][columnName][i].DetectorType)] >
					OrderMap[string(output.Data[table.TableName][columnName][j].DetectorType)] ||

					OrderMap[output.Data[table.TableName][columnName][i].DetectorName] >
						OrderMap[output.Data[table.TableName][columnName][j].DetectorName] ||

					output.Data[table.TableName][columnName][i].Weight > output.Data[table.TableName][columnName][j].Weight
			})

			// Phase 2 Fallback Scan for Unrecognized Columns
			// If column had no column match AND no high/medium value match, test buffered values against RequiresColumnContext entities
			hasValidMatch := false
			for _, item := range output.Data[table.TableName][columnName] {
				if item.Confidence == "High" || item.Confidence == "Medium" {
					hasValidMatch = true
					break
				}
			}

			if !hasValidMatch {
				sampleVals := d.tableScanManager.UnrecognizedValues[table.TableName][columnName]
				if len(sampleVals) > 0 {
					fallbackDetector := NewRegexValueDetector()
					if err := fallbackDetector.Init(); err == nil {
						fallbackContext := ColumnContext{
							PIILabel_BankAccountNumber:     true,
							PIILabel_ChequeNumber:          true,
							PIILabel_CIFNumber:             true,
							PIILabel_LoanAccountNumber:     true,
							PIILabel_InsurancePolicyNumber: true,
							PIILabel_FASTagID:              true,
							PIILabel_CVV:                   true,
							PIILabel_Phone:                 true,
							PIILabel_MICRCode:              true,
							PIILabel_UAN:                   true,
							PIILabel_VoterID:               true,
							PIILabel_PassportNumber:        true,
							PIILabel_TAN:                   true,
							PIILabel_DrivingLicenceNumber:  true,
						}

						labelHits := make(map[PIILabel]int)
						labelWeights := make(map[PIILabel]float64)

						for _, val := range sampleVals {
							labels, _ := fallbackDetector.Detect(context.TODO(), val, fallbackContext)
							for _, lbl := range labels {
								labelHits[lbl.PIILabel]++
								labelWeights[lbl.PIILabel] += lbl.Weight
							}
						}

						totalSamples := len(sampleVals)
						for lbl, hits := range labelHits {
							if hits > 0 {
								// Average weight over sampled values
								avgWeight := labelWeights[lbl] / float64(totalSamples)
								// Phase 2: column name unrecognized → cap at Medium 🟡 (never High 🔴)
								if avgWeight >= 0.70 {
									avgWeight = 0.69
								}
								piiDataWithWeight := NewPIIDataWithWeightString(lbl, avgWeight, DetectorType_ValueDetector, "regex")
								piiDataWithWeight.SetScanedValueAndMatchCount(hits, totalSamples)
								output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
							}
						}

						// Re-sort column findings so top confidence result is first
						sort.Slice(output.Data[table.TableName][columnName], func(i, j int) bool {
							return output.Data[table.TableName][columnName][i].Weight > output.Data[table.TableName][columnName][j].Weight
						})
					}
				}
			}

		}
	}

	// print output to console
	// this code is for testing just to validate the output we are storing here.
	// for table, columnData := range output.Data {
	// 	fmt.Println("Table:", table)
	// 	for column, piiData := range columnData {
	// 		fmt.Println("Column:", column)
	// 		for _, pii := range piiData {
	// 			fmt.Println("Label:", pii.Label, "Confidence:", pii.Confidence, "Weight:", pii.Weight, "DetectorType:", pii.DetectorType, "DetectorName:", pii.DetectorName, "ScanedValueCount:", pii.ScanedValueCount, "MatchedCount:", pii.MatchedCount)
	// 		}
	// 	}
	// }

	return output, nil
}

func getConfidenceLabel(weight float64) (string, string) {
	if weight < 0.4 {
		return "Low", "🔵"
	} else if weight < 0.7 {
		return "Medium", "🟡"
	} else {
		return "High", "🔴"
	}
}

type piiTableScanner struct {
	tableName string
	store     *sql.DB

	tableScanManager *TableScanManager

	runOption  RunOption
	autoDetect bool

	runSpacy bool

	pauseSpinner  func()
	resumeSpinner func()
}

func NewPiiTableScanner(tableName string, store *sql.DB, tableScanManager *TableScanManager, runOption RunOption, autoDetect bool, runSpacy bool, pauseSpinner, resumeSpinner func()) *piiTableScanner {
	return &piiTableScanner{
		tableName: tableName,
		store:     store,
		// catcher:   catcher,
		tableScanManager: tableScanManager,

		runOption:  runOption,
		autoDetect: autoDetect,
		runSpacy:   runSpacy,

		pauseSpinner:  pauseSpinner,
		resumeSpinner: resumeSpinner,
	}
}

func (p *piiTableScanner) processTable(ctx context.Context) error {

	// defer fmt.Println("> Done processing table 1", p.tableName)
	columns, err := p.processColumns(ctx)
	if err != nil {
		return fmt.Errorf("error processing columns: %v", err)
	}

	if len(columns) == 0 {
		return nil
	}

	if p.runOption == RunOption_MetaScan {
		return nil
	}

	coloredTableName := text.Bold.Sprint(p.tableName)

	effectiveOption := p.runOption
	var rowCount int
	if p.autoDetect || p.runOption == RunOption_DataScan || p.runOption == RunOption_DeepScan || p.runOption == RunOption_SpacyScan {
		rowCount, err = utils.TableRowCount(ctx, p.store, p.tableName)
		if err != nil {
			return fmt.Errorf("error getting row count for table %s: %v", p.tableName, err)
		}
		if rowCount == 0 {
			return nil
		}
	}

	if p.autoDetect {
		if rowCount < AUTO_SCAN_ROW_THRESHOLD {
			effectiveOption = RunOption_DeepScan
			if p.pauseSpinner != nil {
				p.pauseSpinner()
			}
			fmt.Println(">", coloredTableName, "has", rowCount, "rows - below threshold of", AUTO_SCAN_ROW_THRESHOLD, "rows, running deep scan")
			if p.resumeSpinner != nil {
				p.resumeSpinner()
			}
		} else {
			effectiveOption = RunOption_DataScan
		}
	}

	if p.runOption == RunOption_DataScan && rowCount < AUTO_SCAN_ROW_THRESHOLD {
		if p.pauseSpinner != nil {
			p.pauseSpinner()
		}
		fmt.Println(">", coloredTableName, "has", rowCount, "rows - Data scan may miss results on tables this small; omit --piiscanner or use --piiscanner deepscan for a full scan")
		if p.resumeSpinner != nil {
			p.resumeSpinner()
		}
	}

	var bar *progressbar.ProgressBar
	var barchan chan struct{}
	if effectiveOption == RunOption_DeepScan || effectiveOption == RunOption_SpacyScan {
		showsPrompt := !yesToAll && rowCount > DEEPSCAN_WARNINING_LIMIT && effectiveOption == RunOption_DeepScan
		showsBar := (p.runSpacy && rowCount > DEEPSCAN_SPACY_WARNING_LIMIT) || rowCount > DEEPSCAN_WARNINING_LIMIT

		if (showsPrompt || showsBar) && p.pauseSpinner != nil {
			p.pauseSpinner()
			defer func() {
				if p.resumeSpinner != nil {
					p.resumeSpinner()
				}
			}()
		}

		if showsPrompt {
			fmt.Print("> ", coloredTableName, " has ", rowCount, " rows. Do you want to continue? (yes=Y | no=N | yes to all=A) : ")
			var input string
			fmt.Scanln(&input) //nolint:errcheck
			if strings.ToLower(input) == "n" {
				return nil
			} else if strings.ToLower(input) == "a" {
				yesToAll = true
			} else if strings.ToLower(input) != "y" {
				return fmt.Errorf("invalid input")
			}
		}
		if showsBar {
			bar = progressbar.NewOptions(rowCount,
				progressbar.OptionSetDescription("Processing "+p.tableName+" table"),
				progressbar.OptionShowCount(),
				progressbar.OptionFullWidth(),
				progressbar.OptionSetItsString("rows"),
				progressbar.OptionShowIts(),
			)

			barchan = make(chan struct{})
			closeChan := make(chan struct{})
			go func() {
				count := 0
				t := time.NewTicker(time.Second)
				for {
					select {
					case <-barchan:
						count++
					case <-t.C:
						bar.Add(count) // nolint:errcheck
						count = 0
					case <-closeChan:
						bar.Finish() //nolint:errcheck
						fmt.Println()
						close(closeChan)
						close(barchan)
						t.Stop()
						// fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed"))
						return
					}
				}
			}()

			// this is to refresh progress bar every second if file is taking more then second to process
			defer func() {
				closeChan <- struct{}{}
			}()
		}
	}

	query := fmt.Sprintf(`SELECT "%s" FROM %s`, strings.Join(columns, `","`), p.tableName)
	if effectiveOption == RunOption_DataScan {
		query = fmt.Sprintf(`SELECT "%s" FROM %s TABLESAMPLE BERNOULLI (10) REPEATABLE (%d) LIMIT 10000`, strings.Join(columns, `","`), p.tableName, DATASCAN_SAMPLE_SEED)
	}

	// defer fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 1"))
	stmt, err := p.store.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v query:(%s)", err, query)
	}

	defer stmt.Close()
	// defer fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 12"))
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()
	// defer fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 123"))

	count := len(columns)

	for rows.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 1234"))
		if barchan != nil {
			barchan <- struct{}{}
		}
		values := make([]interface{}, count)
		scanArgs := make([]interface{}, count)
		for i := range values {
			scanArgs[i] = &values[i]
		}

		err := rows.Scan(scanArgs...)
		if err != nil {
			return fmt.Errorf("error scanning row: %v", err)
		}

		for i := range values {

			val := GetValuesString(values[i])
			if val == "" || val == "NULL" || val == "<nil>" {
				continue
			}

			err := p.tableScanManager.PushValue(ScanInput{
				Tablename:  p.tableName,
				ColumnName: columns[i],
				Value:      val,
			})
			if err != nil {
				return fmt.Errorf("error pushing value: %v", err)
			}
		}

	}

	return nil
}

// func (p *piiTableScanner) getColumns() ([]string, error) {
// 	stmt, err := p.store.Prepare("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '" + p.tableName + "';")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer stmt.Close()

// 	rows, err := stmt.Query()
// 	if err != nil {
// 		return nil, err
// 	}

// 	defer rows.Close()

// 	var columns []string
// 	for rows.Next() {
// 		var column string
// 		var columnType string
// 		err := rows.Scan(&column, &columnType)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if !IgnoreColumn(column) && !IgnoreColumnType(columnType) {
// 			columns = append(columns, column)
// 		}
// 	}

// 	return columns, nil
// }

func (p *piiTableScanner) processColumns(ctx context.Context) ([]string, error) {

	stmt, err := p.store.PrepareContext(ctx, fmt.Sprintf(`SELECT * FROM %s limit 0`, p.tableName))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("error getting columns: %v", err)
	}

	// filter unwanted columns
	columns = FilterColumns(columns)
	if len(columns) == 0 {
		return nil, nil
	}

	for _, column := range columns {
		err := p.tableScanManager.PushColumn(ctx, ScanInput{
			Tablename:  p.tableName,
			ColumnName: column,
		})
		if err != nil {
			return nil, fmt.Errorf("error pushing column: %v", err)
		}
	}

	return columns, nil
}

// func (p *piiTableScanner) processValues(_ context.Context, values map[string]interface{}) error {
// 	for column, value := range values {
// 		err := p.tableScanManager.PushValue(ScanInput{
// 			Tablename:  p.tableName,
// 			ColumnName: column,
// 			Value:      value,
// 		})
// 		if err != nil {
// 			return err
// 		}

// 	}

// 	return nil
// }

// func (p *piiTableScanner) getFinalResult() map[string]PIILabel {
// 	out := make(map[string]PIILabel)

// 	for column, labelScore := range p.result {
// 		maxScore := 0.0
// 		out[column] = ""
// 		for label, score := range labelScore {
// 			if score > maxScore {
// 				maxScore = score
// 				out[column] = label
// 			}
// 		}
// 	}

// 	return out
// }
