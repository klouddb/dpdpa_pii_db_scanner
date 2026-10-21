package piiscanner

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/sqlserverdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
)

type SQLServerAdapter struct {
	cfg    sqlserverdb.SQLServer
	schema string
	db     *sql.DB
}

func NewSQLServerAdapter(cfg sqlserverdb.SQLServer, schema string) *SQLServerAdapter {
	if schema == "" {
		schema = "dbo"
	}
	return &SQLServerAdapter{cfg: cfg, schema: schema}
}

func (a *SQLServerAdapter) Schema() string {
	return a.schema
}

func (a *SQLServerAdapter) Connect(ctx context.Context) error {
	db, err := sqlserverdb.Open(ctx, a.cfg)
	if err != nil {
		return err
	}
	a.db = db
	return nil
}

func (a *SQLServerAdapter) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Close()
}

func (a *SQLServerAdapter) ListTables(ctx context.Context) ([]TableRef, error) {
	var schemaCount int
	err := a.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = '%s'", a.schema)).Scan(&schemaCount)
	if err != nil {
		return nil, err
	}
	if schemaCount == 0 {
		return nil, fmt.Errorf("schema %s does not exist", a.schema)
	}

	names, err := utils.GetListFromQuery(ctx, a.db, fmt.Sprintf(
		"SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema = '%s'",
		a.schema))
	if err != nil {
		return nil, err
	}

	tables := make([]TableRef, len(names))
	for i, name := range names {
		tables[i] = TableRef{Schema: a.schema, Name: name}
	}
	return tables, nil
}

func (a *SQLServerAdapter) quotedName(table TableRef) string {
	return fmt.Sprintf("[%s].[%s]", table.Schema, table.Name)
}

func (a *SQLServerAdapter) ListColumns(ctx context.Context, table TableRef) ([]string, error) {
	stmt, err := a.db.PrepareContext(ctx, fmt.Sprintf(`SELECT TOP 0 * FROM %s`, a.quotedName(table)))
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
	return columns, nil
}

func (a *SQLServerAdapter) RowCount(ctx context.Context, table TableRef) (int, error) {
	return utils.TableRowCount(ctx, a.db, a.quotedName(table))
}

// DetectRowCursor mirrors the Postgres/MySQL versions. SQL Server has no
// is_identity/nextval column in information_schema, so identity columns
// are confirmed via sys.identity_columns instead.
func (a *SQLServerAdapter) DetectRowCursor(ctx context.Context, table TableRef) (RowCursor, bool, error) {
	rows, err := a.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT kcu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = '%s' AND tc.table_name = '%s'`,
		table.Schema, table.Name))
	if err != nil {
		return RowCursor{}, false, fmt.Errorf("error listing primary key columns for %s: %v", table.DisplayName(), err)
	}
	var pkColumns []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			rows.Close()
			return RowCursor{}, false, fmt.Errorf("error scanning primary key column for %s: %v", table.DisplayName(), err)
		}
		pkColumns = append(pkColumns, col)
	}
	if err := rows.Err(); err != nil {
		return RowCursor{}, false, err
	}
	rows.Close()

	if len(pkColumns) != 1 {
		return RowCursor{}, false, nil
	}
	pkColumn := pkColumns[0]

	var dataType string
	err = a.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT data_type FROM information_schema.columns
		WHERE table_schema = '%s' AND table_name = '%s' AND column_name = '%s'`,
		table.Schema, table.Name, pkColumn)).Scan(&dataType)
	if err != nil {
		return RowCursor{}, false, fmt.Errorf("error inspecting primary key column %s for %s: %v", pkColumn, table.DisplayName(), err)
	}
	isNumeric := map[string]bool{"tinyint": true, "smallint": true, "int": true, "bigint": true}[dataType]
	if !isNumeric {
		return RowCursor{}, false, nil
	}

	var isIdentityCount int
	err = a.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT COUNT(*)
		FROM sys.identity_columns c
		JOIN sys.tables t ON c.object_id = t.object_id
		JOIN sys.schemas s ON t.schema_id = s.schema_id
		WHERE s.name = '%s' AND t.name = '%s' AND c.name = '%s'`,
		table.Schema, table.Name, pkColumn)).Scan(&isIdentityCount)
	if err != nil {
		return RowCursor{}, false, fmt.Errorf("error checking identity column %s for %s: %v", pkColumn, table.DisplayName(), err)
	}
	if isIdentityCount == 0 {
		return RowCursor{}, false, nil
	}

	var maxValue sql.NullInt64
	err = a.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT MAX([%s]) FROM %s`, pkColumn, a.quotedName(table))).Scan(&maxValue)
	if err != nil {
		return RowCursor{}, false, fmt.Errorf("error reading max(%s) for %s: %v", pkColumn, table.DisplayName(), err)
	}

	value := "0"
	if maxValue.Valid {
		value = strconv.FormatInt(maxValue.Int64, 10)
	}
	return RowCursor{Column: pkColumn, Kind: CursorKind_Numeric, Value: value}, true, nil
}

func (a *SQLServerAdapter) StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error {
	quotedTable := a.quotedName(table)
	quotedColumns := make([]string, len(columns))
	for i, c := range columns {
		quotedColumns[i] = fmt.Sprintf("[%s]", c)
	}
	columnList := strings.Join(quotedColumns, ",")

	var query string
	switch {
	case opts.Mode == SampleMode_Limited:
		query = fmt.Sprintf(`SELECT TOP %d %s FROM %s TABLESAMPLE (%d ROWS) REPEATABLE (%d)`,
			opts.Size, columnList, quotedTable, opts.Size, opts.Seed)
	case opts.RowCursor != nil:
		cursorVal, err := strconv.ParseInt(opts.RowCursor.Value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid row cursor value %q for %s: %v", opts.RowCursor.Value, opts.RowCursor.Column, err)
		}
		query = fmt.Sprintf(`SELECT %s FROM %s WHERE [%s] > %d`, columnList, quotedTable, opts.RowCursor.Column, cursorVal)
	default:
		query = fmt.Sprintf(`SELECT %s FROM %s`, columnList, quotedTable)
	}

	stmt, err := a.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v query:(%s)", err, query)
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	count := len(columns)

	values := make([]interface{}, count)
	scanArgs := make([]interface{}, count)
	for i := range values {
		scanArgs[i] = &values[i]
	}
	for rows.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if onRowScanned != nil {
			onRowScanned()
		}

		if err := rows.Scan(scanArgs...); err != nil {
			return fmt.Errorf("error scanning row: %v", err)
		}

		for i := range values {
			val := GetValuesString(values[i])
			if val == "" || val == "NULL" || val == "<nil>" {
				continue
			}
			if err := cb(columns[i], val); err != nil {
				return err
			}
		}
	}

	return rows.Err()
}
