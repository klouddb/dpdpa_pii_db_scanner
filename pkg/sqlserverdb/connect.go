package sqlserverdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

type SQLServer struct {
	Host      string
	Port      string
	User      string
	Password  string
	DBName    string
	Encrypt   string // "", "disable", "true", "false"
	PingCheck bool

	// Certificate is the path to a CA cert file used for chain validation —
	// needed for RDS/Aurora SQL Server, which presents a cert signed by
	// Amazon's RDS CA rather than a publicly trusted root.
	Certificate string
	// HostNameInCertificate overrides the hostname checked against the
	// server certificate's subject. RDS/Aurora certs are issued for the
	// cluster's wildcard name, not the literal endpoint hostname, so this
	// is usually required alongside Certificate.
	HostNameInCertificate string
}

func buildDSN(conf SQLServer) string {
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(conf.User, conf.Password),
		Host:   fmt.Sprintf("%s:%s", conf.Host, conf.Port),
	}
	q := url.Values{}
	q.Set("database", conf.DBName)
	if conf.Encrypt != "" {
		q.Set("encrypt", conf.Encrypt)
	}
	if conf.Certificate != "" {
		q.Set("certificate", conf.Certificate)
	}
	if conf.HostNameInCertificate != "" {
		q.Set("hostnameincertificate", conf.HostNameInCertificate)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func Open(ctx context.Context, conf SQLServer) (*sql.DB, error) {
	db, err := sql.Open("sqlserver", buildDSN(conf))
	if err != nil {
		return nil, fmt.Errorf("connect to SQL Server host=%q port=%q database=%q user=%q: %w", conf.Host, conf.Port, conf.DBName, conf.User, err)
	}

	if conf.PingCheck {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, fmt.Errorf("connect to SQL Server host=%q port=%q database=%q user=%q: %w", conf.Host, conf.Port, conf.DBName, conf.User, err)
		}
	}

	return db, nil
}
