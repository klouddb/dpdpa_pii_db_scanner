package piiscanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
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

	// Incremental enables differential scanning: only new tables/columns or
	// tables that need a deeper scan are re-scanned; existing results are
	// carried forward from the state file.
	Incremental bool
}

func NewConfig(runOption, excludeTable, includeTable, database, schema string, printAllResults, spacyOnly, printSummaryOnly bool, incremental bool) (*Config, error) {

	if printAllResults && printSummaryOnly {
		return nil, fmt.Errorf("--print-all and --print-summary are not allowed together")
	}

	if database == "" {
		return nil, errors.New("database name is required")
	}

	// Incremental is incompatible with metascan (no value data recorded) and
	// spacyscan (uses a different detection pipeline not tracked in state).
	if incremental {
		if runOption == RunOption_MetaScan_String {
			return nil, fmt.Errorf("--incremental cannot be used with --piiscanner metascan: meta scan does not record value-level findings in state")
		}
		if runOption == RunOption_SpacyScan_String || spacyOnly {
			return nil, fmt.Errorf("--incremental cannot be used with spacyscan or --spacy-only")
		}
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

	out := &Config{
		runOption:        r,
		AutoDetect:       autoDetect,
		useSpacy:         useSpacy,
		Database:         database,
		Schema:           schema,
		printAllResults:  printAllResults,
		spacyOnly:        spacyOnly,
		PrintSummaryOnly: printSummaryOnly,
		Incremental:      incremental,
	}

	if excludeTable != "" {
		out.excludeTable = utils.NewSetFromSlice(utils.TrimSpaceArray(strings.Split(excludeTable, ",")))
	}

	if includeTable != "" {
		out.includeTable = utils.TrimSpaceArray(strings.Split(includeTable, ","))
	}

	return out, nil
}

type databasePiiScanner struct {
	adapter          DBAdapter
	tableScanManager *TableScanManager

	numOfRunners int
	cnf          *Config
	spinner      *scanningSpinner

	// incremental scan state
	stateFilePath   string
	previousState   *HostDbState          // loaded at scan start; nil = no prior state
	carriedFindings map[string]TableState // tableName → findings carried forward from state

	// liveTableNames is the full, unfiltered set of tables that exist in the
	// database right now (independent of --include-table/--exclude-table).
	// Lets BuildStateSnapshot tell "excluded from this run" (keep the old
	// state entry) apart from "dropped from the database" (delete it).
	liveTableNames map[string]bool

	// effectiveDepth records, per table, the depth actually used this run
	// ("datascan"/"deepscan"). In auto-detect mode this is decided per table
	// from its row count, so it can't be derived from a single cnf.runOption.
	effectiveDepth   map[string]string
	effectiveDepthMu sync.Mutex

	// rowDiffOnlyColumns marks, per table, which columns were scanned in
	// "new rows only" mode this run (as opposed to a full column scan).
	// GetResults() needs this to know which carried findings must be
	// additively merged rather than replaced outright.
	rowDiffOnlyColumns map[string]map[string]bool

	// detectedCursors holds a freshly-detected cursor for tables that got a
	// full scan this run OUTSIDE the carriedFindings bookkeeping.
	// BuildStateSnapshot reads this so a baseline gets recorded even when
	// --incremental wasn't used this run.
	detectedCursors map[string]RowCursor
}

func NewDatabasePiiScanner(adapter DBAdapter, cnf *Config) *databasePiiScanner {
	return &databasePiiScanner{
		adapter:        adapter,
		numOfRunners:   runtime.NumCPU(),
		cnf:            cnf,
		effectiveDepth: make(map[string]string),
	}
}

// recordEffectiveDepth stores the depth actually used for a table this run.
func (d *databasePiiScanner) recordEffectiveDepth(tableName, depth string) {
	d.effectiveDepthMu.Lock()
	defer d.effectiveDepthMu.Unlock()
	d.effectiveDepth[tableName] = depth
}

// for safe reads of the mutex-guarded map
func (d *databasePiiScanner) getEffectiveDepth(tableName string) string {
	d.effectiveDepthMu.Lock()
	defer d.effectiveDepthMu.Unlock()
	return d.effectiveDepth[tableName]
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
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
		detectors = append(detectors, NewRegexValueDetectorForRegion(RegionIndia))
	}

	if d.cnf.useSpacy {
		detectors = append(detectors, NewSpacyDetector().WithWorkDirs([]string{"python", "/etc/klouddbshield/python", "../../python"}))
	}

	return detectors
}

func (d *databasePiiScanner) GetTables(ctx context.Context) ([]TableRef, error) {
	if len(d.cnf.includeTable) != 0 {
		tables := make([]TableRef, len(d.cnf.includeTable))
		for i, name := range d.cnf.includeTable {
			tables[i] = TableRef{Schema: d.cnf.Schema, Name: name}
		}
		return tables, nil
	}

	tables, err := d.adapter.ListTables(ctx)
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

	// ── State bookkeeping: load previous state + the full live table set ─────
	// Runs whenever a state file is wired at all — default runs included, not
	// just --incremental — so BuildStateSnapshot can correctly preserve state
	// for tables outside this run's scope (--include-table/--exclude-table)
	// while still dropping tables genuinely gone from the database.
	if d.stateFilePath != "" {
		state, err := LoadState(d.stateFilePath)
		if err != nil {
			if d.cnf.Incremental {
				if os.IsNotExist(err) {
					fmt.Printf("> [incremental] no previous state found for %s/%s — running full scan\n",
						d.previousState.Host, d.cnf.Database)
				} else {
					fmt.Printf("> [incremental] warning: could not load state (%v) — running full scan\n", err)
				}
			}
			d.previousState = nil
		} else {
			d.previousState = state
		}
		if d.cnf.Incremental {
			d.carriedFindings = make(map[string]TableState)
		}

		liveTables := tables
		if len(d.cnf.includeTable) != 0 {
			// GetTables() returned only the --include-table subset in this
			// case, not the real live list — fetch it separately.
			var err error
			liveTables, err = d.adapter.ListTables(ctx)
			if err != nil {
				return fmt.Errorf("error listing tables for state bookkeeping: %v", err)
			}
		}
		d.liveTableNames = make(map[string]bool, len(liveTables))
		for _, t := range liveTables {
			d.liveTableNames[t.DisplayName()] = true
		}
	}
	// ─────────────────────────────────────────────────────────────────────────

	d.tableScanManager = NewTableScanManager().WithColumnDetector(NewRegexColumnDetectorForRegion(RegionIndia))
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

	var skippedCount, newTableCount, newColumnCount, depthUpgradeCount, newRowsCount, baselineEstablishedCount int

	explicitDeepscan := !d.cnf.AutoDetect && d.cnf.runOption == RunOption_DeepScan

	for _, table := range tables {
		if d.cnf.excludeTable != nil && d.cnf.excludeTable.Contains(table.Name) {
			continue
		}

		var segments []scanSegment
		var knownRowCount *int

		if d.cnf.Incremental {
			if d.previousState == nil {
				// First-ever --incremental run for this host+database
				// (or right after --reset-incremental) — no baseline to
				// diff against, so every table is effectively new.
				newTableCount++
			} else {
				d.pauseSpinner()
				tableName := table.DisplayName()
				prevTable, existed := d.previousState.Tables[tableName]

				if existed {
					prevColSet := make(map[string]bool, len(prevTable.Columns))
					for _, c := range prevTable.Columns {
						prevColSet[c] = true
					}
					rawColumns, err := d.adapter.ListColumns(ctx, table)
					if err != nil {
						return fmt.Errorf("error listing columns for %s: %v", tableName, err)
					}
					liveColumns := FilterColumns(rawColumns)
					liveColSet := make(map[string]bool, len(liveColumns))
					for _, c := range liveColumns {
						liveColSet[c] = true
					}

					var newColumns []string
					for _, c := range liveColumns {
						if !prevColSet[c] {
							newColumns = append(newColumns, c)
						}
					}

					// Recorded columns that no longer exist live — prune
					// them from whatever gets carried forward.
					var droppedColumns []string
					keptColumns := make([]string, 0, len(prevTable.Columns))
					keptFindings := make(map[string][]PIIDataWithWeightString, len(prevTable.Findings))
					for _, c := range prevTable.Columns {
						if liveColSet[c] {
							keptColumns = append(keptColumns, c)
							if f, ok := prevTable.Findings[c]; ok {
								keptFindings[c] = f
							}
						} else {
							droppedColumns = append(droppedColumns, c)
						}
					}
					if len(droppedColumns) > 0 {
						fmt.Print(text.FgHiMagenta.Sprintf("> %s: %d column(s) no longer exist %v — removing from recorded state\n",
							tableName, len(droppedColumns), droppedColumns))
					}

					requestedDepth, rowCount, hasRowCount, err := d.requestedDepthForTable(ctx, table)
					if err != nil {
						return err
					}
					if hasRowCount {
						rc := rowCount
						knownRowCount = &rc
					}
					depthOK := IsDepthSufficient(prevTable.Depth, requestedDepth)

					switch {
					case !depthOK:
						// prevTable.Depth == datascan, requestedDepth ==
						// deepscan — the only way depthOK can be false,
						// since deepscan-saved always satisfies any request.
						depthUpgradeCount++
						fmt.Print(text.FgHiMagenta.Sprintf("> %s: depth insufficient (%s < %s) — running full value rescan\n",
							tableName, prevTable.Depth, requestedDepth))
						// Falls through to a full, unrestricted scan below.

					case prevTable.Depth == Depth_DataScan:
						// depthOK == true here implies requestedDepth ==
						// datascan too. Cursor is never involved for a
						// sampled table — a sample was never meant to be
						// exhaustive, so there's no "new rows" guarantee to
						// chase.
						if len(newColumns) == 0 {
							skippedCount++
							d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: prevTable.Depth, Findings: keptFindings}
							d.resumeSpinner()
							continue
						}
						newColumnCount++
						fmt.Print(text.FgHiMagenta.Sprintf("> %s: %d new column(s) detected %v — scanning new column(s) only, existing columns carried forward\n",
							tableName, len(newColumns), newColumns))
						d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: requestedDepth, Findings: keptFindings}
						segments = []scanSegment{{columns: toSet(newColumns)}}

					default:
						// prevTable.Depth == deepscan. depthOK == true
						// regardless of what's requested — deepscan always
						// satisfies any ask, whether that's an explicit
						// deepscan, an explicit datascan, or auto-detect.
						// Cursor logic only activates on an explicit
						// --piiscanner deepscan run; otherwise this behaves
						// exactly like today, and a cursor still gets
						// silently captured afterward as a bonus (see the
						// "opportunistic cursor capture" block below).
						if !explicitDeepscan {
							if len(newColumns) == 0 {
								skippedCount++
								d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: prevTable.Depth, Findings: keptFindings, RowCursor: prevTable.RowCursor}
								d.resumeSpinner()
								continue
							}
							newColumnCount++
							fmt.Print(text.FgHiMagenta.Sprintf("> %s: %d new column(s) detected %v — scanning new column(s) only, existing columns carried forward\n",
								tableName, len(newColumns), newColumns))
							d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: requestedDepth, Findings: keptFindings, RowCursor: prevTable.RowCursor}
							segments = []scanSegment{{columns: toSet(newColumns)}}
							break
						}

						cursor, cursorOK, cursorErr := d.adapter.DetectRowCursor(ctx, table)
						if cursorErr != nil {
							return fmt.Errorf("error detecting row cursor for %s: %v", tableName, cursorErr)
						}

						var advanced bool
						haveBaseline := false
						if cursorOK && prevTable.RowCursor != nil {
							advanced, err = CursorAdvanced(*prevTable.RowCursor, cursor)
							if err != nil {
								// Cursor column/kind changed since last run
								// (e.g. the primary key was redefined) —
								// treat like "not found," not a hard error.
								cursorOK = false
							} else {
								haveBaseline = true
							}
						}

						switch {
						case !cursorOK:
							// Genuinely no cursor column available this run,
							// OR the previously recorded cursor no longer
							// matches
							fmt.Print(text.FgHiMagenta.Sprintf("> %s: row cursor unavailable (schema/PK changed) — skipping row-level diff, only checking for new columns\n", tableName))
							if len(newColumns) == 0 {
								skippedCount++
								d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: prevTable.Depth, Findings: keptFindings}
								d.resumeSpinner()
								continue
							}
							newColumnCount++
							fmt.Print(text.FgHiMagenta.Sprintf("> %s: %d new column(s) detected %v — scanning new column(s) only, existing columns carried forward\n",
								tableName, len(newColumns), newColumns))
							d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: requestedDepth, Findings: keptFindings}
							segments = []scanSegment{{columns: toSet(newColumns)}}

						case !haveBaseline:
							// A cursor column exists now, but there's no
							// previous baseline to compare against — it just
							// became valid (e.g. the column was just made an
							// identity PK), or this is the first run to
							// notice it. We can't tell whether rows arrived
							// while this table had no cursor tracked — it
							// was being silently skipped until now — so
							// treat this like a first-ever deepscan: full
							// rescan now, then start tracking the cursor
							// from here.
							baselineEstablishedCount++
							fmt.Print(text.FgHiMagenta.Sprintf("> %s: cursor newly available (%s) — running full scan once to establish a baseline\n",
								tableName, cursor.Column))
							if d.detectedCursors == nil {
								d.detectedCursors = make(map[string]RowCursor)
							}
							d.detectedCursors[tableName] = cursor

						default:
							// Cursor exists and we have a previous baseline to compare against.
							if !advanced && len(newColumns) == 0 {
								skippedCount++
								d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: prevTable.Depth, Findings: keptFindings, RowCursor: &cursor}
								d.resumeSpinner()
								continue
							}

							d.carriedFindings[tableName] = TableState{Columns: keptColumns, Depth: requestedDepth, Findings: keptFindings, RowCursor: &cursor}

							if advanced {
								newRowsCount++
								fmt.Print(text.FgHiMagenta.Sprintf("> %s: new rows detected (cursor %s: %s -> %s) — scanning new rows only for existing columns\n",
									tableName, cursor.Column, prevTable.RowCursor.Value, cursor.Value))
								if d.rowDiffOnlyColumns == nil {
									d.rowDiffOnlyColumns = make(map[string]map[string]bool)
								}
								if d.rowDiffOnlyColumns[tableName] == nil {
									d.rowDiffOnlyColumns[tableName] = make(map[string]bool, len(keptColumns))
								}
								for _, c := range keptColumns {
									d.rowDiffOnlyColumns[tableName][c] = true
								}
								lastCursor := *prevTable.RowCursor
								segments = append(segments, scanSegment{columns: toSet(keptColumns), rowCursor: &lastCursor})
							}
							if len(newColumns) > 0 {
								newColumnCount++
								fmt.Print(text.FgHiMagenta.Sprintf("> %s: %d new column(s) detected %v — scanning new column(s) only, existing columns carried forward\n",
									tableName, len(newColumns), newColumns))
								segments = append(segments, scanSegment{columns: toSet(newColumns)})
							}
						}
					}
				} else {
					newTableCount++
					fmt.Print(text.FgHiMagenta.Sprintf("> %s: new table found — running full value scan\n", table.DisplayName()))
				}
				d.resumeSpinner()
			}
		}

		var preScanCursor RowCursor
		var preScanCursorOK bool
		if d.stateFilePath != "" {
			if _, alreadyCarried := d.carriedFindings[table.DisplayName()]; !alreadyCarried {
				if cursor, ok, err := d.adapter.DetectRowCursor(ctx, table); err == nil && ok {
					preScanCursor = cursor
					preScanCursorOK = true
				}
			}
		}

		err := initFunction()
		if err != nil {
			return fmt.Errorf("error starting table scan manager: %v", err)
		}

		s := NewTableScanner(table, d.adapter, d.tableScanManager, d.cnf.runOption, d.cnf.AutoDetect, d.cnf.useSpacy, d.pauseSpinner, d.resumeSpinner, d.recordEffectiveDepth, segments, knownRowCount)
		if err := s.processTable(ctx); err != nil {
			return fmt.Errorf("error processing table %s: %v", table.DisplayName(), err)
		}

		// Opportunistic cursor capture: independent of --incremental. Uses
		// preScanCursor (detected BEFORE processTable ran) rather than
		// re-detecting afterward — a post-scan MAX(id) would see rows
		// inserted while the scan was in progress, even though the scan's
		// own snapshot never actually read them, producing a watermark
		// higher than what was really covered and silently skipping those
		// rows on every future incremental run.
		if preScanCursorOK {
			_, alreadyCarried := d.carriedFindings[table.DisplayName()]
			_, alreadyDetected := d.detectedCursors[table.DisplayName()]
			if !alreadyCarried && !alreadyDetected && d.getEffectiveDepth(table.DisplayName()) == Depth_DeepScan {
				if d.detectedCursors == nil {
					d.detectedCursors = make(map[string]RowCursor)
				}
				d.detectedCursors[table.DisplayName()] = preScanCursor
			}
		}
	}

	if d.cnf.Incremental {
		d.pauseSpinner()
		fmt.Printf("> [incremental] summary: %d table(s) skipped (already covered), %d new table(s), %d table(s) with new columns, %d table(s) with new rows, %d table(s) establishing a new cursor baseline, %d table(s) rescanned for depth\n",
			skippedCount, newTableCount, newColumnCount, newRowsCount, baselineEstablishedCount, depthUpgradeCount)
		d.resumeSpinner()
	}

	return nil
}

// requestedDepthForTable returns the depth that will actually be applied to
// this table in the current run. In auto-detect mode it also returns the row
// count it queried to decide that, so the caller can pass it on to
// processTable() and avoid paying for a second COUNT(*) on the same table.
func (d *databasePiiScanner) requestedDepthForTable(ctx context.Context, table TableRef) (depth string, rowCount int, hasRowCount bool, err error) {
	switch d.cnf.runOption {
	case RunOption_DeepScan:
		return Depth_DeepScan, 0, false, nil
	case RunOption_DataScan:
		return Depth_DataScan, 0, false, nil
	default:
		rowCount, err = d.adapter.RowCount(ctx, table)
		if err != nil {
			return "", 0, false, fmt.Errorf("error getting row count for %s: %v", table.DisplayName(), err)
		}
		if rowCount < AUTO_SCAN_ROW_THRESHOLD {
			return Depth_DeepScan, rowCount, true, nil
		}
		return Depth_DataScan, rowCount, true, nil
	}
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

// mergeFindingsAdditive combines two findings slices for the same column,
// summing counts for matching (Label, DetectorType, DetectorName) entries.
// Used only for columns scanned in "new rows only" mode, where fresh
// reflects just the new rows, not the whole table — unlike a full column
// scan, it must be added to carried, not replace it.
func mergeFindingsAdditive(carried, fresh []PIIDataWithWeightString) []PIIDataWithWeightString {
	type key struct {
		label   PIILabel
		detType DetectorType
		detName string
	}
	merged := make(map[key]*PIIDataWithWeightString, len(carried)+len(fresh))
	order := make([]key, 0, len(carried)+len(fresh))

	for _, item := range carried {
		item := item
		k := key{item.Label, item.DetectorType, item.DetectorName}
		merged[k] = &item
		order = append(order, k)
	}
	for _, item := range fresh {
		k := key{item.Label, item.DetectorType, item.DetectorName}
		if existing, ok := merged[k]; ok {
			totalScanned := existing.ScanedValueCount + item.ScanedValueCount
			if totalScanned > 0 {
				existing.Weight = (existing.Weight*float64(existing.ScanedValueCount) + item.Weight*float64(item.ScanedValueCount)) / float64(totalScanned)
			}
			existing.ScanedValueCount = totalScanned
			existing.MatchedCount += item.MatchedCount
			existing.Confidence, existing.ConfidenceIcon = getConfidenceLabel(existing.Weight)
		} else {
			item := item
			merged[k] = &item
			order = append(order, k)
		}
	}

	out := make([]PIIDataWithWeightString, 0, len(order))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	return out
}

func (d *databasePiiScanner) GetResults() (*DatabasePIIScanOutput, error) {
	if d.tableScanManager == nil {
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

	fallbackDetector := NewRegexValueDetector()
	fallbackDetectorReady := fallbackDetector.Init() == nil
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
			unknownColumn := len(piiMap.ColumnMap) == 0
			var results []PIIDataWithWeightString
			for detector, piiData := range piiMap.ValueMap {
				for label, pii := range piiData {

					if count != 0 {
						ratio := float64(pii.Count) / float64(count)
						if unknownColumn && ratio < 0.30 {
							continue
						}
					}

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
					results = append(results, *piiDataWithWeight)
				}
			}
			output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], getBestLabel(results)...)

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
					if fallbackDetectorReady {
						fallbackContext := ColumnContext{
							PIILabel_Phone:                true,
							PIILabel_VoterID:              true,
							PIILabel_PassportNumber:       true,
							PIILabel_TAN:                  true,
							PIILabel_DrivingLicenceNumber: true,
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
							if hits == 0 {
								continue
							}
							ratio := float64(hits) / float64(totalSamples)
							if ratio < 0.30 {
								continue
							}
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

	// ── Incremental: merge carried-forward findings ───────────────────────────
	for tableName, carried := range d.carriedFindings {
		if _, exists := output.Data[tableName]; !exists {
			output.Data[tableName] = make(TableDetailOutput)
		}
		for columnName, piis := range carried.Findings {
			fresh, hasFresh := output.Data[tableName][columnName]
			switch {
			case !hasFresh:
				// Live scan produced nothing for this column this run
				// (skipped entirely, or a new-rows-only scan found no
				// matches) — carried findings are still the whole truth.
				output.Data[tableName][columnName] = piis
			case d.rowDiffOnlyColumns[tableName][columnName]:
				// Fresh findings only cover the new rows scanned this run —
				// add to, don't replace, what was already known.
				output.Data[tableName][columnName] = mergeFindingsAdditive(piis, fresh)
			default:
				// Fresh findings cover the whole column (new column, or a
				// full rescan) — they supersede the carried ones entirely.
			}
		}
	}
	// ─────────────────────────────────────────────────────────────────────────

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

// scanSegment describes one pass over a table's data: which columns to
// read (nil = every live column), and whether to restrict it to rows added
// after a cursor watermark (nil = every row). A table normally scans in a
// single segment; it needs two only when a DeepScan incremental run finds
// both new columns (which need their full history) and a usable row cursor
// for columns it already knew about (which only need the new rows).
type scanSegment struct {
	columns   map[string]bool
	rowCursor *RowCursor
}

type tableScanner struct {
	table   TableRef
	adapter DBAdapter

	tableScanManager *TableScanManager

	runOption  RunOption
	autoDetect bool
	runSpacy   bool

	pauseSpinner  func()
	resumeSpinner func()

	onDepthDecided func(tableName, depth string)

	// segments describes what to scan. nil or empty means "everything, in
	// one pass" — today's default behavior.
	segments []scanSegment

	// knownRowCount, when set, is a row count already fetched by the
	// incremental decision logic — processTable() uses it instead of
	// querying RowCount() again.
	knownRowCount *int
}

func NewTableScanner(table TableRef, adapter DBAdapter, tableScanManager *TableScanManager, runOption RunOption, autoDetect bool, runSpacy bool, pauseSpinner, resumeSpinner func(), onDepthDecided func(tableName, depth string), segments []scanSegment, knownRowCount *int) *tableScanner {
	return &tableScanner{
		table: table, adapter: adapter,
		tableScanManager: tableScanManager,
		runOption:        runOption,
		autoDetect:       autoDetect,
		runSpacy:         runSpacy,
		pauseSpinner:     pauseSpinner,
		resumeSpinner:    resumeSpinner,
		onDepthDecided:   onDepthDecided,
		segments:         segments,
		knownRowCount:    knownRowCount,
	}
}

func getBestLabel(entries []PIIDataWithWeightString) []PIIDataWithWeightString {
	if len(entries) <= 1 {
		return entries
	}

	rank := map[string]int{"High": 3, "Medium": 2, "Low": 1}
	best := 0
	for _, e := range entries {
		if rank[e.Confidence] > best {
			best = rank[e.Confidence]
		}
	}

	var topTier []PIIDataWithWeightString
	maxMatched := 0
	for _, e := range entries {
		if rank[e.Confidence] == best {
			topTier = append(topTier, e)
			if e.MatchedCount > maxMatched {
				maxMatched = e.MatchedCount
			}
		}
	}

	var winners []PIIDataWithWeightString
	for _, e := range topTier {
		if e.MatchedCount == maxMatched {
			winners = append(winners, e)
		}
	}
	return winners
}

// liveColumns returns every currently-scannable column for this table.
func (p *tableScanner) liveColumns(ctx context.Context) ([]string, error) {
	rawColumns, err := p.adapter.ListColumns(ctx, p.table)
	if err != nil {
		return nil, err
	}
	return FilterColumns(rawColumns), nil
}

// resolveSegmentColumns intersects a segment's target columns with what's
// live right now, and registers the result with the column-name detector.
// Returns an empty slice if the segment has nothing left to scan.
func (p *tableScanner) resolveSegmentColumns(ctx context.Context, live []string, seg scanSegment) ([]string, error) {
	columns := live
	if seg.columns != nil {
		columns = nil
		for _, c := range live {
			if seg.columns[c] {
				columns = append(columns, c)
			}
		}
	}
	for _, column := range columns {
		err := p.tableScanManager.PushColumn(ctx, ScanInput{
			Tablename:  p.table.DisplayName(),
			ColumnName: column,
		})
		if err != nil {
			return nil, fmt.Errorf("error pushing column: %v", err)
		}
	}
	return columns, nil
}

func (p *tableScanner) processTable(ctx context.Context) error {
	live, err := p.liveColumns(ctx)
	if err != nil {
		return fmt.Errorf("error processing columns: %v", err)
	}
	if len(live) == 0 {
		return nil
	}
	if p.runOption == RunOption_MetaScan {
		// MetaScan only cares about column names/existence — register every
		// live column once and stop; it never uses segmented row scanning.
		for _, column := range live {
			if err := p.tableScanManager.PushColumn(ctx, ScanInput{
				Tablename:  p.table.DisplayName(),
				ColumnName: column,
			}); err != nil {
				return fmt.Errorf("error pushing column: %v", err)
			}
		}
		return nil
	}

	displayName := p.table.DisplayName()
	coloredTableName := text.Bold.Sprint(displayName)

	effectiveOption := p.runOption
	var rowCount int
	if p.autoDetect || p.runOption == RunOption_DataScan || p.runOption == RunOption_DeepScan || p.runOption == RunOption_SpacyScan {
		if p.knownRowCount != nil {
			rowCount = *p.knownRowCount
		} else {
			rowCount, err = p.adapter.RowCount(ctx, p.table)
			if err != nil {
				return fmt.Errorf("error getting row count for table %s: %v", displayName, err)
			}
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

	if p.onDepthDecided != nil {
		depth := Depth_DataScan
		if effectiveOption == RunOption_DeepScan {
			depth = Depth_DeepScan
		}
		p.onDepthDecided(displayName, depth)
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
				progressbar.OptionSetDescription("Processing "+displayName+" table"),
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
						bar.Add(count) //nolint:errcheck
						count = 0
					case <-closeChan:
						bar.Finish() //nolint:errcheck
						fmt.Println()
						close(closeChan)
						close(barchan)
						t.Stop()
						return
					}
				}
			}()

			defer func() {
				closeChan <- struct{}{}
			}()
		}
	}

	onRowScanned := func() {
		if barchan != nil {
			barchan <- struct{}{}
		}
	}

	segments := p.segments
	if len(segments) == 0 {
		segments = []scanSegment{{}}
	}

	for _, seg := range segments {
		segColumns, err := p.resolveSegmentColumns(ctx, live, seg)
		if err != nil {
			return err
		}
		if len(segColumns) == 0 {
			continue
		}

		opts := SampleOptions{Mode: SampleMode_Full, RowCursor: seg.rowCursor}
		if effectiveOption == RunOption_DataScan {
			opts = SampleOptions{Mode: SampleMode_Limited, Size: 10000, Seed: DATASCAN_SAMPLE_SEED}
		}

		err = p.adapter.StreamValues(ctx, p.table, segColumns, opts, onRowScanned, func(columnName, value string) error {
			return p.tableScanManager.PushValue(ScanInput{
				Tablename:  displayName,
				ColumnName: columnName,
				Value:      value,
			})
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// Helper functions for differential scan feature

// SetStateFilePath tells the scanner where to load and save its incremental
// state file. Must be called before Scan().
func (d *databasePiiScanner) SetStateFilePath(path string, host string) {
	d.stateFilePath = path
	// Pre-populate Host so the "no previous state" message can name the host.
	d.previousState = &HostDbState{
		Host:     host,
		Database: d.cnf.Database,
		Tables:   make(map[string]TableState),
	}
}

// BuildStateSnapshot assembles a HostDbState from the current scan's processed
// output plus any findings that were carried forward from the previous state.
// Must be called after GetResults() succeeds, passing its return value as output.
func (d *databasePiiScanner) BuildStateSnapshot(host, database, engine string, output *DatabasePIIScanOutput) *HostDbState {
	state := &HostDbState{
		Host:     host,
		Database: database,
		Engine:   engine,
		Tables:   make(map[string]TableState),
	}

	// Seed from whatever was carried forward — a whole-table skip, or just
	// the existing columns of a table that got a new-columns-only scan.
	for tableName, carried := range d.carriedFindings {
		findings := make(map[string][]PIIDataWithWeightString, len(carried.Findings))
		for c, f := range carried.Findings {
			findings[c] = f
		}
		state.Tables[tableName] = TableState{
			Columns:   append([]string{}, carried.Columns...),
			Depth:     carried.Depth,
			Findings:  findings,
			RowCursor: carried.RowCursor,
		}
	}

	// Merge in freshly-scanned columns: a brand new table, a full rescan, or
	// just the new columns of a table whose old columns were seeded above.
	if output != nil {
		for tableName, columnData := range output.Data {
			existing, hasCarried := state.Tables[tableName]
			if !hasCarried {
				depth := d.effectiveDepth[tableName]
				if depth == "" {
					depth = Depth_DataScan
				}
				existing = TableState{Depth: depth, Findings: make(map[string][]PIIDataWithWeightString)}
				if depth == Depth_DeepScan {
					if cursor, ok := d.detectedCursors[tableName]; ok {
						c := cursor
						existing.RowCursor = &c
					}
				}
			}

			colSet := make(map[string]bool, len(existing.Columns))
			for _, c := range existing.Columns {
				colSet[c] = true
			}
			for columnName, piis := range columnData {
				if !colSet[columnName] {
					existing.Columns = append(existing.Columns, columnName)
					colSet[columnName] = true
				}
				if len(piis) > 0 {
					existing.Findings[columnName] = piis
				}
			}
			state.Tables[tableName] = existing
		}
	}

	// Preserve tables merely out of this run's scope; drop ones genuinely
	// gone from the live database.
	if d.previousState != nil {
		for tableName, prevTableState := range d.previousState.Tables {
			if _, exists := state.Tables[tableName]; exists {
				continue
			}
			if d.liveTableNames[tableName] {
				state.Tables[tableName] = prevTableState
			}
		}
	}

	return state
}
