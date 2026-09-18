package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/postgresdb"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/mongodb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/mysqldb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/redisdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/sqlserverdb"
)

var version = "dev"

type InstanceConfig struct {
	Engine string `toml:"engine"` // "postgres" (default), "mysql", "mongodb", "sqlserver", "redis"

	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Username string `toml:"username"` // redis ACL username, optional
	Password string `toml:"password"`

	Databases []string `toml:"databases"` // postgres, mysql, sqlserver, mongodb
	RedisDBs  []int    `toml:"redis_dbs"` // redis only

	URI string `toml:"uri"` // mongodb connection string

	SSLmode     string `toml:"sslmode"` // postgres
	SSLcert     string `toml:"sslcert"`
	SSLkey      string `toml:"sslkey"`
	SSLrootcert string `toml:"sslrootcert"`

	TLSMode string `toml:"tlsmode"` // mysql
	Encrypt string `toml:"encrypt"` // sqlserver

	Certificate           string `toml:"certificate"`           // sqlserver: path to CA cert (e.g. RDS CA bundle), for RDS/Aurora
	HostNameInCertificate string `toml:"hostnameincertificate"` // sqlserver: hostname to check against the cert, usually needed for RDS/Aurora
}

type AppConfig struct {
	Instances []InstanceConfig `toml:"instances"`
}

const defaultConfigPath = "/etc/dpdpascanner/config.toml"

const defaultScanTimeout = 10 * time.Minute

func resolveConfigPath(configDir string) (string, error) {
	if configDir != "" {
		return filepath.Join(configDir, "config.toml"), nil
	}

	if cwdPath := filepath.Join(".", "config.toml"); fileExists(cwdPath) {
		return cwdPath, nil
	}
	if fileExists(defaultConfigPath) {
		return defaultConfigPath, nil
	}

	return "", fmt.Errorf("config.toml not found in current directory or %s; use --config to specify its location, or pass a postgres:// URI", defaultConfigPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func defaultPort(engine string) int {
	switch engine {
	case piiscanner.Engine_MySQL:
		return 3306
	case piiscanner.Engine_SQLServer:
		return 1433
	case piiscanner.Engine_Redis:
		return 6379
	default:
		return 5432
	}
}

func instanceLabel(inst InstanceConfig, engine string, port int) (display string, dirSafe string) {
	safe := strings.NewReplacer(":", "_", ",", "_", "/", "_")
	if engine == piiscanner.Engine_MongoDB {
		u, err := url.Parse(inst.URI)
		if err != nil || u.Host == "" {
			log.Printf("  [SKIP] MongoDB instance has missing/invalid uri: %q", inst.URI)
			return "", "" // caller should skip this instance — see note below
		}
		host := u.Host
		safe := strings.NewReplacer(":", "_", ",", "_", "/", "_").Replace(host)
		return host, safe
	}
	display = fmt.Sprintf("%s:%d", inst.Host, port)
	return display, safe.Replace(display)
}

// effectiveHost returns the host used for display, state-file naming, and
// --target-host matching. Every engine except MongoDB sets Host directly
// in config.toml; MongoDB specifies a uri instead, so its host is parsed
// out of that URI.
func effectiveHost(inst InstanceConfig) string {
	if inst.Host != "" {
		return inst.Host
	}
	if inst.URI != "" {
		if u, err := url.Parse(inst.URI); err == nil {
			return u.Hostname()
		}
	}
	return ""
}

func main() {
	configDir := flag.String("config", "", "directory containing config.toml (default: current directory, falling back to /etc/dpdpascanner)")
	runOption := flag.String("piiscanner", "", "scan type: datascan | metascan | deepscan | spacyscan (leave empty for automatic per-table selection)")
	engineFilter := flag.String("engine", "", "scan only this engine: postgres | mysql | mongodb | sqlserver | redis (leave empty to scan all)")
	dbFilter := flag.String("database", "", "scan only this database (leave empty to scan all)")
	schema := flag.String("schema", "", "schema to scan (postgres default: public, sqlserver default: dbo; ignored by mysql, mongodb, redis)")
	excludeTable := flag.String("exclude-table", "", "comma-separated list of tables to exclude")
	includeTable := flag.String("include-table", "", "comma-separated list of tables to include")
	targetHost := flag.String("target-host", "", "scan only this host (leave empty to scan all)")
	printAll := flag.Bool("print-all", false, "include low/medium confidence results in terminal, log files, and HTML report (default: high confidence only)")
	printSummary := flag.Bool("print-summary", false, "print summary only")
	noTimeout := flag.Bool("no-timeout", false, fmt.Sprintf("disable the %s per-database scan timeout, useful for very large databases that need more time", defaultScanTimeout))
	showVersion := flag.Bool("version", false, "print version and exit")
	incremental := flag.Bool("incremental", false, "only scan new tables/columns or tables needing a deeper scan since the previous run")
	resetIncremental := flag.Bool("reset-incremental", false, "delete the scan_state/ folder to reset previous scan states")
	flag.Parse()

	// Handle --reset-incremental before anything else.
	if *resetIncremental {
		removed, err := piiscanner.ResetStateFolder()
		if err != nil {
			log.Fatalf("Failed to reset incremental state: %v", err)
		}
		if removed {
			fmt.Println("> scan_state/ folder removed — all previous scan states cleared")
		} else {
			fmt.Println("> scan_state/ folder did not exist — nothing to reset")
		}
		if !*incremental {
			// If only --reset-incremental was given (no --incremental), stop here.
			return
		}
	}

	if *showVersion {
		fmt.Println("> dpdpascanner version: " + version)
		return
	}

	if *runOption != "" && !piiscanner.IsValidRunOption(*runOption) {
		opts := piiscanner.RunOptionSlice()
		sort.Strings(opts)
		log.Fatalf("Invalid --piiscanner value: %q. Must be one of: %s", *runOption, strings.Join(opts, ", "))
	}

	if *incremental {
		if *runOption == piiscanner.RunOption_MetaScan_String {
			log.Fatalf("--incremental cannot be used with --piiscanner metascan")
		}
		if *runOption == piiscanner.RunOption_SpacyScan_String {
			log.Fatalf("--incremental cannot be used with --piiscanner spacyscan")
		}
	}

	if *engineFilter != "" && !piiscanner.IsValidEngine(*engineFilter) {
		log.Fatalf("Invalid --engine value: %q. Must be one of: postgres, mysql, mongodb, sqlserver, redis", *engineFilter)
	}

	args := flag.Args()
	if len(args) > 1 {
		log.Fatalf("unexpected arguments: %v", args)
	}

	// Optional: postgres://... as a CLI string (not stored). Skips config.toml.
	if len(args) == 1 {
		uri := args[0]
		if !postgresdb.IsConnectionURI(uri) {
			log.Fatalf("unexpected argument %q (expected postgres:// URI or no args for config.toml)", uri)
		}
		if *configDir != "" || *dbFilter != "" || *targetHost != "" {
			log.Fatal("with a postgres:// URI do not use --config, --database, or --target-host")
		}

		db, host, database, err := postgresdb.OpenURI(uri)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\n=== Scanning %s / %s ===\n", host, database)
		adapter := piiscanner.NewPostgresAdapterFromDB(db, *schema)

		stateFile := ""
		if piiscanner.SupportsIncrementalState(*runOption) {
			stateFile = piiscanner.GetStateFilePath(host, database)
		}
		runScan(adapter, host, database, *runOption, *excludeTable, *includeTable, *printAll, *printSummary, *noTimeout, *incremental, stateFile, piiscanner.Engine_Postgres, filepath.Join("scan_results", database))

		return
	}

	configPath, err := resolveConfigPath(*configDir)
	if err != nil {
		log.Fatal(err)
	}
	var cfg AppConfig
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		log.Fatalf("Failed to load config.toml from %s: %v", configPath, err)
	}
	if len(cfg.Instances) == 0 {
		log.Fatal("No instances defined in config.toml")
	}

	if *targetHost != "" {
		hostMatched := false
		for _, inst := range cfg.Instances {
			if effectiveHost(inst) == *targetHost {
				hostMatched = true
				break
			}
		}
		if !hostMatched {
			log.Fatalf("host %q not found in config.toml", *targetHost)
		}
	}

	if *engineFilter != "" {
		engineMatched := false
		for _, inst := range cfg.Instances {
			if piiscanner.NormalizeEngine(inst.Engine) == *engineFilter {
				engineMatched = true
				break
			}
		}
		if !engineMatched {
			log.Fatalf("engine %q not found in config.toml", *engineFilter)
		}
	}

	baseOutputDir := "scan_results"
	if err := os.RemoveAll(baseOutputDir); err != nil {
		log.Printf("Warning: failed to remove existing %s directory: %v", baseOutputDir, err)
	}

	type scanTarget struct {
		name    string // database name, or "db0"/"db1" style label for redis
		redisDB int    // only meaningful when engine == redis
	}

	dbMatched := false
	for _, inst := range cfg.Instances {
		if *targetHost != "" && effectiveHost(inst) != *targetHost {
			continue
		}

		engine := piiscanner.NormalizeEngine(inst.Engine)
		if !piiscanner.IsValidEngine(engine) {
			log.Printf("  [SKIP] host %s: invalid engine %q", inst.Host, inst.Engine)
			continue
		}

		if *engineFilter != "" && engine != *engineFilter {
			continue
		}

		port := inst.Port
		if port == 0 {
			port = defaultPort(engine)
		}

		var targets []scanTarget
		if engine == piiscanner.Engine_Redis {
			dbs := inst.RedisDBs
			if len(dbs) == 0 {
				dbs = []int{0}
			}
			for _, n := range dbs {
				targets = append(targets, scanTarget{name: fmt.Sprintf("db%d", n), redisDB: n})
			}
		} else {
			for _, name := range inst.Databases {
				targets = append(targets, scanTarget{name: name})
			}
		}

		for _, t := range targets {
			if *dbFilter != "" && t.name != *dbFilter {
				continue
			}
			dbMatched = true

			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("  [SKIP] panic while scanning %s/%s: %v", inst.Host, t.name, r)
					}
				}()

				label, dirLabel := instanceLabel(inst, engine, port)
				if dirLabel == "" {
					return
				}
				dbOutputDir := filepath.Join(baseOutputDir, fmt.Sprintf("%s_%s", dirLabel, t.name))
				fmt.Printf("\n=== Scanning %s / %s (%s) ===\n", label, t.name, engine)

				engineCfg := piiscanner.EngineConfig{
					Engine: engine,
					Schema: *schema,
					Postgres: postgresdb.Postgres{
						Host: inst.Host, Port: strconv.Itoa(port), User: inst.User, Password: inst.Password,
						DBName: t.name, SSLmode: inst.SSLmode, SSLcert: inst.SSLcert, SSLkey: inst.SSLkey, SSLrootcert: inst.SSLrootcert,
						PingCheck: true,
					},
					MySQL: mysqldb.MySQL{
						Host: inst.Host, Port: strconv.Itoa(port), User: inst.User, Password: inst.Password,
						DBName: t.name, TLSMode: inst.TLSMode, PingCheck: true,
					},
					Mongo: mongodb.Mongo{
						URI: inst.URI, DBName: t.name,
					},
					SQLServer: sqlserverdb.SQLServer{
						Host: inst.Host, Port: strconv.Itoa(port), User: inst.User, Password: inst.Password,
						DBName: t.name, Encrypt: inst.Encrypt, PingCheck: true,
						Certificate: inst.Certificate, HostNameInCertificate: inst.HostNameInCertificate,
					},
					Redis: redisdb.Redis{
						Host: inst.Host, Port: strconv.Itoa(port), Username: inst.Username, Password: inst.Password,
						DB: t.redisDB, PingCheck: true,
					},
				}

				adapter, err := piiscanner.NewAdapter(engineCfg)
				if err != nil {
					log.Printf("  [SKIP] %v", err)
					return
				}

				if err := adapter.Connect(context.Background()); err != nil {
					log.Printf("  [SKIP] Could not connect: %v", err)
					adapter.Close()
					return
				}

				stateFile := ""
				isIncremental := *incremental
				if engine == piiscanner.Engine_Redis {
					if *incremental {
						fmt.Println("> [incremental] Redis engine does not support incremental scanning — running full scan")
					}
					isIncremental = false
				} else if piiscanner.SupportsIncrementalState(*runOption) {
					stateFile = piiscanner.GetStateFilePath(dirLabel, t.name)
				}
				runScan(adapter, effectiveHost(inst), t.name, *runOption, *excludeTable, *includeTable, *printAll, *printSummary, *noTimeout, isIncremental, stateFile, engine, dbOutputDir)
			}()
		}
	}
	if *dbFilter != "" && !dbMatched {
		log.Fatalf("database %q not found in config.toml", *dbFilter)
	}
}

func runScan(adapter piiscanner.DBAdapter, host, database, runOption, excludeTable, includeTable string, printAll, printSummary, noTimeout, incremental bool, stateFilePath, engine, outputDir string) {
	defer adapter.Close()

	cnf, err := piiscanner.NewConfig(runOption, excludeTable, includeTable, database, adapter.Schema(), printAll, false, printSummary, incremental)
	if err != nil {
		log.Printf("  [SKIP] Config error: %v", err)
		return
	}

	scanner := piiscanner.NewDatabasePiiScanner(adapter, cnf)

	// Wire state file path whenever one applies (metascan/spacyscan already
	// got "" earlier) — not just for --incremental runs. BuildStateSnapshot
	// needs the previous state loaded on every run so it can preserve/drop
	// out-of-scope tables correctly, even on a default full scan.
	if stateFilePath != "" {
		scanner.SetStateFilePath(stateFilePath, host)
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if noTimeout {
		ctx, cancel = context.Background(), func() {}
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), defaultScanTimeout)
	}
	err = scanner.Scan(ctx)
	cancel()

	if err != nil {
		scanner.Close()
		log.Printf("  [SKIP] Scan error: %v", err)
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("  Scan of %s stopped after the %s timeout — re-run with --no-timeout to let it finish without a time limit.", database, defaultScanTimeout)
		}
		return
	}

	output, err := scanner.GetResults()
	if err != nil || output == nil {
		log.Printf("  [SKIP] No results returned")
		return
	}

	piiscanner.PrintTerminalOutput(output, cnf.OutputOptions())
	piiscanner.CreateTabularOutputfile(output, cnf.OutputOptions(), outputDir)
	piiscanner.CreateHTMLReport(output, *cnf, host, engine, outputDir)

	// Persist state baseline for table-structured engines (Postgres, MySQL, SQLServer, Mongo).
	// Skipped for Redis (stateFilePath == "").
	if stateFilePath != "" {
		state := scanner.BuildStateSnapshot(host, database, engine, output)
		if err := piiscanner.SaveStateAtomic(stateFilePath, state); err != nil {
			log.Printf("> [state] warning: could not save scan state: %v", err)
		}
	}
}
