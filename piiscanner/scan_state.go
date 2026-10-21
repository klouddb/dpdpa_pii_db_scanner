package piiscanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StateDirName is the folder where per-database state files are persisted.
// Unlike scan_results/, this folder is NEVER wiped on startup.
const StateDirName = "scan_state"

// TableState stores what the scanner found for one table in a previous run:
// the column list, the scan depth achieved, and the PII findings per column.
type TableState struct {
	Columns []string `json:"columns"`
	Depth   string   `json:"depth"` // "datascan" or "deepscan"
	
	// RowCursor is the row-level incremental watermark for this table.
	// Only ever set when Depth == "deepscan".
	RowCursor *RowCursor `json:"row_cursor,omitempty"`

	Findings map[string][]PIIDataWithWeightString `json:"findings"`
}

// HostDbState is the top-level structure saved to disk per host+database pair.
type HostDbState struct {
	Host        string                `json:"host"`
	Database    string                `json:"database"`
	Engine      string                `json:"engine"`
	LastScanned time.Time             `json:"last_scanned"`
	Tables      map[string]TableState `json:"tables"`
}

// GetStateFilePath returns the path to the state file for a given
// host+database combination. dirLabel is already the safe "host_port" string
// produced by instanceLabel() in main.go.
func GetStateFilePath(dirLabel, dbName string) string {
	safeLabel := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "_").Replace(dirLabel)
	safeDB := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "_").Replace(dbName)
	fileName := fmt.Sprintf("%s_%s.json", safeLabel, safeDB)
	return filepath.Join(StateDirName, fileName)
}

// LoadState reads and parses a state file from disk.
// Returns (nil, os.ErrNotExist) when no file exists yet — callers use this
// to detect "first run" and print the "no previous state found" warning.
func LoadState(filePath string) (*HostDbState, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var state HostDbState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("error parsing state file %s: %w", filePath, err)
	}
	if state.Tables == nil {
		state.Tables = make(map[string]TableState)
	}
	return &state, nil
}

// SaveStateAtomic writes state to disk using a .tmp → rename swap so a
// crash mid-write never leaves a corrupted state file.
func SaveStateAtomic(filePath string, state *HostDbState) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("error creating state directory: %w", err)
	}

	state.LastScanned = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling state: %w", err)
	}

	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("error writing temp state file: %w", err)
	}

	// On Windows, Rename fails if the destination already exists,
	// so we remove it first and then rename.
	_ = os.Remove(filePath)
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("error finalising state file: %w", err)
	}
	return nil
}

// IsDepthSufficient returns true when the depth recorded in a previous scan
// covers the depth being requested now.
//
// Hierarchy: deepscan > datascan
//   - deepscan covers both deepscan and datascan requests → always true
//   - datascan only covers datascan requests
func IsDepthSufficient(recordedDepth, requestedDepth string) bool {
	recordedDepth = strings.ToLower(recordedDepth)
	requestedDepth = strings.ToLower(requestedDepth)

	if recordedDepth == Depth_DeepScan {
		return true
	}
	if recordedDepth == Depth_DataScan {
		return requestedDepth == Depth_DataScan
	}
	return false
}

// ResetStateFolder deletes the entire scan_state/ directory.
// Returns (true, nil) if it existed and was removed, (false, nil) if it
// wasn't there in the first place.
func ResetStateFolder() (bool, error) {
	if _, err := os.Stat(StateDirName); os.IsNotExist(err) {
		return false, nil
	}
	if err := os.RemoveAll(StateDirName); err != nil {
		return false, fmt.Errorf("failed to remove %s directory: %w", StateDirName, err)
	}
	return true, nil
}

// SupportsIncrementalState reports whether a run option participates in the
// scan_state system at all. MetaScan and SpacyScan are fully outside this
// system — they neither read nor write state, regardless of --incremental —
// so callers must not even compute a state file path for them.
func SupportsIncrementalState(runOption string) bool {
	return runOption != RunOption_MetaScan_String && runOption != RunOption_SpacyScan_String
}
