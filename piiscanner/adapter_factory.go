package piiscanner

import (
	"fmt"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/mongodb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/mysqldb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/postgresdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/redisdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/sqlserverdb"
)

const (
	Engine_Postgres  = "postgres"
	Engine_MySQL     = "mysql"
	Engine_MongoDB   = "mongodb"
	Engine_SQLServer = "sqlserver"
	Engine_Redis     = "redis"
)

// NormalizeEngine treats an empty engine string as "postgres", so every
// config.toml written before multi-engine support existed keeps working
// unchanged — no one is forced to add `engine = "postgres"` retroactively.
func NormalizeEngine(engine string) string {
	if engine == "" {
		return Engine_Postgres
	}
	return engine
}

func IsValidEngine(engine string) bool {
	switch NormalizeEngine(engine) {
	case Engine_Postgres, Engine_MySQL, Engine_MongoDB, Engine_SQLServer, Engine_Redis:
		return true
	}
	return false
}

// EngineConfig carries connection settings for every engine side by side;
// NewAdapter only reads the block matching Engine, the rest is ignored.
type EngineConfig struct {
	Engine string
	Schema string // used by postgres and sqlserver only

	Postgres  postgresdb.Postgres
	MySQL     mysqldb.MySQL
	Mongo     mongodb.Mongo
	SQLServer sqlserverdb.SQLServer
	Redis     redisdb.Redis
}

func NewAdapter(cfg EngineConfig) (DBAdapter, error) {
	switch NormalizeEngine(cfg.Engine) {
	case Engine_Postgres:
		return NewPostgresAdapter(cfg.Postgres, cfg.Schema), nil
	case Engine_MySQL:
		return NewMySQLAdapter(cfg.MySQL), nil
	case Engine_MongoDB:
		return NewMongoAdapter(cfg.Mongo), nil
	case Engine_SQLServer:
		return NewSQLServerAdapter(cfg.SQLServer, cfg.Schema), nil
	case Engine_Redis:
		return NewRedisAdapter(cfg.Redis), nil
	default:
		return nil, fmt.Errorf("unknown engine %q", cfg.Engine)
	}
}