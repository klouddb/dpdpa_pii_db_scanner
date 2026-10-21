package piiscanner

import (
	"context"
	"fmt"
	"strconv"
)

// TableRef identifies one scannable unit within a data source —
// a SQL table, a Mongo collection, a Redis keyspace, etc.
// Callers treat it as an opaque handle; only the adapter that produced it
// knows how to actually query it.
type TableRef struct {
	Schema string
	Name   string
}

func (t TableRef) DisplayName() string {
	if t.Schema == "" {
		return t.Name
	}
	return t.Schema + "." + t.Name
}

// SampleMode controls how much of a table an adapter reads.
type SampleMode int

const (
	SampleMode_Full    SampleMode = iota // DeepScan: read everything
	SampleMode_Limited                   // DataScan: read up to Size rows
)

type SampleOptions struct {
	Mode SampleMode
	Size int // used only when Mode == SampleMode_Limited
	Seed int // reproducible sampling, where the engine supports it

	// RowCursor, when set, restricts StreamValues to rows added after this
	// watermark (i.e. Column > Value). Only ever used for the DeepScan
	// "scan new rows only" incremental pass — DataScan never sets this.
	RowCursor *RowCursor
}

// CursorKind identifies how a RowCursor's Value should be compared.
// Timestamp-based cursors are deferred for later
type CursorKind string

const (
	// CursorKind_Numeric is a single-column numeric auto-increment /
	// identity / serial primary key. Value is a base-10 integer string.
	CursorKind_Numeric CursorKind = "numeric"

	// CursorKind_ObjectID is Mongo's _id. Value is its 24-char hex string.
	CursorKind_ObjectID CursorKind = "objectid"
)

// RowCursor is a bookmark for row-level incremental scanning: "every row
// with Column <= Value has already been scanned." Produced only for tables
// with a single-column numeric primary key (SQL engines) or Mongo's _id —
// see DBAdapter.DetectRowCursor. Composite/non-numeric PKs, tables with no
// PK, and Redis (no row concept) never produce one.
type RowCursor struct {
	Column string
	Kind   CursorKind
	Value  string
}

// CursorAdvanced reports whether current represents rows inserted after
// saved was recorded. Returns an error if the two aren't comparable
// (different column or kind, e.g. the table's PK changed between runs) —
// callers must treat that as "cursor unusable, fall back to today's
// column-diff-only behavior," not as "new rows found."
func CursorAdvanced(saved, current RowCursor) (bool, error) {
	if saved.Column != current.Column || saved.Kind != current.Kind {
		return false, fmt.Errorf("saved cursor (%s/%s) is not comparable to current cursor (%s/%s)",
			saved.Column, saved.Kind, current.Column, current.Kind)
	}
	switch saved.Kind {
	case CursorKind_Numeric:
		savedVal, err := strconv.ParseInt(saved.Value, 10, 64)
		if err != nil {
			return false, fmt.Errorf("invalid saved cursor value %q: %w", saved.Value, err)
		}
		currentVal, err := strconv.ParseInt(current.Value, 10, 64)
		if err != nil {
			return false, fmt.Errorf("invalid current cursor value %q: %w", current.Value, err)
		}
		return currentVal > savedVal, nil
	case CursorKind_ObjectID:
		return current.Value > saved.Value, nil
	default:
		return false, fmt.Errorf("unknown cursor kind %q", saved.Kind)
	}
}

// RowCallback fires once per non-empty value found while scanning a table —
// this is exactly where piiTableScanner today calls tableScanManager.PushValue.
type RowCallback func(columnName string, value string) error

// DBAdapter is the contract every supported database engine must implement.
// TableScanManager, the Detectors, and the report generator never see this
// interface directly — only the table-scanning orchestrator talks to it.
type DBAdapter interface {
	Connect(ctx context.Context) error
	Close() error

	// Schema returns the resolved schema this adapter operates against
	// (e.g. "public" for Postgres, "dbo" for SQL Server, the database
	// name for MySQL). Engines without a schema concept (Mongo, Redis)
	// return "".
	Schema() string

	// ListTables enumerates scannable units: tables, collections, etc.
	ListTables(ctx context.Context) ([]TableRef, error)

	// ListColumns enumerates column/field names for one table.
	ListColumns(ctx context.Context, table TableRef) ([]string, error)

	// RowCount estimates size, used for the DataScan-vs-DeepScan
	// auto-detect threshold. An approximation is fine.
	RowCount(ctx context.Context, table TableRef) (int, error)

	// StreamValues reads the table per opts, invoking cb once per
	// non-empty cell in every requested column.
	StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error

	// DetectRowCursor looks for a column that can act as a row-level
	// incremental watermark for this table and, if found, returns its
	// current maximum value.
	// ok is false when no such column exists (composite or non-numeric
	// primary key, no primary key at all) or the engine doesn't support
	// this concept at all (Redis always returns false).
	DetectRowCursor(ctx context.Context, table TableRef) (cursor RowCursor, ok bool, err error)
}
