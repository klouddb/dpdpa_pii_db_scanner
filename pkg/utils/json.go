package utils

import (
	"context"
	"database/sql"
	"fmt"
)

func SchemaExists(ctx context.Context, store *sql.DB, schemaName string) (bool, error) {
	var schemaExists bool
	err := store.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)", schemaName).Scan(&schemaExists)
	if err != nil {
		return false, err
	}
	return schemaExists, nil
}

func TableRowCount(ctx context.Context, store *sql.DB, tableName string) (int, error) {
	var count int
	err := store.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, tableName)).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func GetListFromQuery(ctx context.Context, store *sql.DB, sqlString string) ([]string, error) {
	list := []string{}
	rows, err := store.QueryContext(ctx, sqlString)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}

	defer rows.Close()

	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if v == "" {
			continue
		}

		list = append(list, v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return list, nil
}
