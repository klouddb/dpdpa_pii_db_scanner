package mysqldb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

type MySQL struct {
	Host      string
	Port      string
	User      string
	Password  string
	DBName    string
	TLSMode   string // "", "true", "skip-verify", "preferred"
	PingCheck bool
}

func Open(ctx context.Context, conf MySQL) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User = conf.User
	cfg.Passwd = conf.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%s", conf.Host, conf.Port)
	cfg.DBName = conf.DBName
	cfg.ParseTime = true
	if conf.TLSMode != "" {
		cfg.TLSConfig = conf.TLSMode
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("connect to MySQL host=%q port=%q database=%q user=%q: %w", conf.Host, conf.Port, conf.DBName, conf.User, err)
	}

	if conf.PingCheck {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, fmt.Errorf("connect to MySQL host=%q port=%q database=%q user=%q: %w", conf.Host, conf.Port, conf.DBName, conf.User, err)
		}
	}

	return db, nil
}
