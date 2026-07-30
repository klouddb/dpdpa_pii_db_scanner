package postgresdb

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

type Postgres struct {
	Host        string `toml:"host"`
	Port        string `toml:"port"`
	User        string `toml:"user"`
	Password    string `toml:"password"`
	DBName      string `toml:"dbname"`
	SSLmode     string `toml:"sslmode"`
	SSLcert     string `toml:"sslcert"`
	SSLkey      string `toml:"sslkey"`
	SSLrootcert string `toml:"sslrootcert"`
	PingCheck   bool   `toml:"pingCheck"`
	MaxIdleConn int    `toml:"maxIdleConn"`
	MaxOpenConn int    `toml:"maxOpenConn"`
}

// Open opens the PostgreSQL database connection specified by its connection
// string, which can be of the format described at:
// https://pkg.go.dev/github.com/lib/pq#hdr-Connection_String_Parameters

// BuildConnectionString builds a PostgreSQL connection string from the given configuration
func BuildConnectionString(conf Postgres) string {
	var parts []string

	parts = append(parts,
		formatConnectionParameter("host", conf.Host),
		formatConnectionParameter("port", conf.Port),
		formatConnectionParameter("user", conf.User),
	)
	if conf.Password != "" {
		parts = append(parts, formatConnectionParameter("password", conf.Password))
	}
	parts = append(parts, formatConnectionParameter("dbname", conf.DBName))

	if conf.SSLmode != "" {
		parts = append(parts, formatConnectionParameter("sslmode", conf.SSLmode))
	} else {
		parts = append(parts, "sslmode=require")
	}
	if conf.SSLcert != "" {
		parts = append(parts, formatConnectionParameter("sslcert", conf.SSLcert))
	}
	if conf.SSLkey != "" {
		parts = append(parts, formatConnectionParameter("sslkey", conf.SSLkey))
	}
	if conf.SSLrootcert != "" {
		parts = append(parts, formatConnectionParameter("sslrootcert", conf.SSLrootcert))
	}

	return strings.Join(parts, " ")
}

func formatConnectionParameter(key, value string) string {
	if !strings.ContainsAny(value, " \t\r\n'\\=") {
		return key + "=" + value
	}

	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return key + "='" + escaped + "'"
}

func Open(conf Postgres) (*sql.DB, string, error) {
	if err := validateSSLMode(conf.SSLmode); err != nil {
		return nil, "", err
	}

	url := BuildConnectionString(conf)

	db, err := ConnectDatabaseUsingConnectionString(url, conf.PingCheck)
	if err != nil {
		return nil, "", fmt.Errorf(
			"connect to PostgreSQL host=%q port=%q database=%q user=%q: %w",
			conf.Host,
			conf.Port,
			conf.DBName,
			conf.User,
			err,
		)
	}
	if conf.MaxIdleConn > 0 {
		db.SetMaxIdleConns(conf.MaxIdleConn)
	}
	if conf.MaxOpenConn > 0 {
		db.SetMaxOpenConns(conf.MaxOpenConn)
	}

	hostname := conf.Host
	if hostname == "" {
		log.Error().Msg("PostgreSQL host is empty")
		hostname = "unknown"
	}

	return db, hostname, nil
}

func validateSSLMode(mode string) error {
	switch mode {
	case "", "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return nil
	default:
		return fmt.Errorf(
			"invalid PostgreSQL sslmode %q (valid values: disable, allow, prefer, require, verify-ca, verify-full)",
			mode,
		)
	}
}

// ConnectDatabaseUsingConnectionString connects to a PostgreSQL database using the provided connection string.
// It returns a database connection, the connection string, and an error if any.
func ConnectDatabaseUsingConnectionString(url string, pingCheck bool) (*sql.DB, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Failed to open database connection")
		return nil, err
	}

	if pingCheck {
		err = db.Ping()
		if err != nil {
			log.Error().
				Err(err).
				Msg("Failed to ping database")
			db.Close()
			return nil, err
		}
	}

	return db, nil
}
