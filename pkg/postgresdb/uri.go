package postgresdb

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
)

// IsConnectionURI reports whether s looks like a PostgreSQL connection URI.
func IsConnectionURI(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://")
}

// OpenURI connects using the URI string as-is (not stored, not converted to
// keyword params). host and dbname are returned only for display / reports.
func OpenURI(uri string) (*sql.DB, string, string, error) {
	host, dbname, err := uriHostAndDB(uri)
	if err != nil {
		return nil, "", "", err
	}

	db, err := ConnectDatabaseUsingConnectionString(uri, true)
	if err != nil {
		return nil, "", "", fmt.Errorf("connect with URI host=%q database=%q: %w", host, dbname, err)
	}
	return db, host, dbname, nil
}

func uriHostAndDB(uri string) (host, dbname string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", fmt.Errorf("invalid PostgreSQL connection URI: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
	default:
		return "", "", fmt.Errorf("unsupported connection URI scheme %q (expected postgres:// or postgresql://)", u.Scheme)
	}

	host = u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("connection URI is missing a host")
	}

	dbname = strings.Trim(strings.TrimPrefix(u.Path, "/"), "/")
	if decoded, decErr := url.PathUnescape(dbname); decErr == nil {
		dbname = decoded
	}
	if dbname == "" {
		return "", "", fmt.Errorf("connection URI is missing a database name")
	}
	return host, dbname, nil
}
