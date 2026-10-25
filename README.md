# DPDPA Scanner — India's Digital Personal Data Protection Act

[![Go Build](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/release.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/release.yml) [![Go Lint](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/golangci.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/golangci.yml) [![Govulncheck](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/govulncheck.yml)

A command-line PII scanner built for compliance with India's **Digital Personal Data Protection (DPDP) Act 2023**.

Point it at a database — PostgreSQL, MySQL, SQL Server, MongoDB, or Redis — and it scans every table (or collection/key) for sensitive data: Aadhaar, PAN, GSTIN, bank accounts, credit cards, passports, UPI IDs, and 40+ other entity types. Results show up in your terminal, in log files, and in a self-contained HTML report.

## What you get

- **Terminal output** — high-confidence findings by default; add `--print-all` for medium/low confidence too
- **HTML report** (`kshield_pii_report.html`) — same findings, browsable, no internet needed to open it
- **Log files** — `kshield_pii_highconfidence.log` always; `kshield_pii_lowconfidence.log` with `--print-all`
- **Multi-instance scanning** — any mix of servers, engines, and databases in one run via `config.toml`
- **Incremental scans** — re-run later and only scan what's new or under-scanned (`--incremental`)

Each table is scanned two ways: a **meta scan** (column names only, e.g. a column called `aadhaar_number`) and a **data scan** (actual values checked against 40+ regex patterns). By default the scanner picks the right depth automatically per table — see [Scan modes](#scan-modes) below.

## Prerequisites

- Go 1.26 or newer (to build)
- Git
- One of: PostgreSQL, MySQL, SQL Server, MongoDB, or Redis
- Optional, only for `--piiscanner spacyscan`: Python 3 with spaCy installed

## Getting started

**1. Clone and build**

```bash
git clone https://github.com/klouddb/dpdpa_pii_db_scanner.git
cd dpdpa_pii_db_scanner
go build -o dpdpascanner ./cmd/
```

This produces a single `dpdpascanner` binary. Rebuild only when the code changes.

**2. Configure**

Copy `conf.example.toml` to `config.toml` and edit it, or skip this step entirely and pass a connection URI on the command line (Postgres only — see below).

`config.toml` is gitignored, so credentials never get committed.

```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password_here"
databases = ["my_database"]
sslmode   = "require"   # "disable" only for trusted local dev
```

Add an `engine` field for anything other than Postgres:

```toml
[[instances]]
engine    = "mysql"        # mysql | sqlserver | mongodb | redis
host      = "localhost"
port      = 3306
user      = "mysql_user"
password  = "your_password_here"
databases = ["my_database"]
```

MongoDB uses a `uri` instead of host/port/user/password, and Redis uses `redis_dbs` (a list of numbered databases) instead of `databases`. See `conf.example.toml` for a worked example of every engine, including TLS options for production/RDS-style setups.

**3. Run it**

```bash
./dpdpascanner
```

With no flags, this scans everything in `config.toml` using the recommended automatic depth. That's the right first command to run.

## Common flags

| Flag                                  | Default                                 | What it does                                                                    |
| ------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------- |
| `--config`                            | current directory                       | Folder containing `config.toml`                                                 |
| `--engine`                            | _(all engines)_                         | Scan only one engine: `postgres`, `mysql`, `mongodb`, `sqlserver`, `redis`      |
| `--database`                          | _(all databases)_                       | Scan only this one database                                                     |
| `--target-host`                       | _(all hosts)_                           | Scan only this server                                                           |
| `--schema`                            | `public` (Postgres), `dbo` (SQL Server) | Schema to scan; ignored by MySQL/MongoDB/Redis                                  |
| `--include-table` / `--exclude-table` | _(none)_                                | Comma-separated table allow/deny list                                           |
| `--piiscanner`                        | _(not set — see below)_                 | Force one mode everywhere: `datascan`, `metascan`, `deepscan`, `spacyscan`      |
| `--print-all`                         | `false`                                 | Include medium/low confidence findings, not just high                           |
| `--print-summary`                     | `false`                                 | Print a condensed summary instead of full tables                                |
| `--incremental`                       | `false`                                 | Skip tables/columns already scanned deeply enough in a previous run             |
| `--reset-incremental`                 | `false`                                 | Delete saved incremental state and exit                                         |
| `--no-timeout`                        | `false`                                 | Disable the default per-database scan timeout (useful for very large databases) |
| `--version`                           | —                                       | Print version and exit                                                          |

Instead of `--config`/`--database`/`--target-host`, you can pass a Postgres connection URI directly:

```bash
./dpdpascanner "postgres://user:pass@localhost:5432/mydb?sslmode=disable"
```

## Scan modes

- **Default (no `--piiscanner` flag)** — small tables (under 10,000 rows) get a full deep scan; large tables get a fast ~10% sample. This is the recommended way to run the scanner day to day.
- **`datascan`** — always samples ~10% of rows (up to 10,000), regardless of table size. Fast, but can miss rare values on small tables.
- **`metascan`** — column names only, no data ever read. Fastest option, and useful where you're not allowed to read row values at all.
- **`deepscan`** — every row, no sampling. Thorough but slow on large tables; scanning a table over 100,000 rows will ask for confirmation first.
- **`spacyscan`** — runs a spaCy NER model against columns already flagged as Name/Address, to double-check those specific findings. See below.

## Incremental scanning

Pass `--incremental` and the scanner remembers what it already covered, per host and database, in JSON files under `scan_state/`. On the next run it skips anything already scanned at sufficient depth (a prior deep scan satisfies a later data scan request) and only looks at new or shallower tables. Run `--reset-incremental` to wipe that state and start fresh. It doesn't apply to `metascan`, `spacyscan`, or Redis (which always does a full scan).

## Understanding the output

**Terminal** — a live progress view per table, followed by a findings table:

```
=== Scanning localhost:5432 / sales_db ===
> Found 12 tables
> Started table scan manager with 8 runners

Data Scan Report
+----------------+----------+-------+------------+----------+---------+
| TABLE          | COLUMN   | LABEL | CONFIDENCE | DETECTOR | MATCHED |
+----------------+----------+-------+------------+----------+---------+
| public.users   | email    | Email | High 🔴    | regex    | 101/101 |
+----------------+----------+-------+------------+----------+---------+

Meta Scan Report
+----------------+----------+----------+------------+
| TABLE          | COLUMN   | LABEL    | CONFIDENCE |
+----------------+----------+----------+------------+
| public.users   | dob      | BirthDate| High 🔴    |
+----------------+----------+----------+------------+

> High confidence log file created at: [ /path/to/kshield_pii_highconfidence.log ]
> HTML report created at: [ /path/to/kshield_pii_report.html ]
```

With `--print-all`, the low-confidence log line is also printed. If nothing was found at all, you'll simply see `> No PII data found in database`.

**HTML report** (`kshield_pii_report.html`) — summary cards, findings tables, and colour-coded PII labels. It's overwritten on every run, so if you're scanning several databases in one go and want to keep a report per database, scan them one at a time with `--database`.

**Log files** — `kshield_pii_highconfidence.log` and (with `--print-all`) `kshield_pii_lowconfidence.log`, written to the folder you ran the scanner from.

## PII entities detected (40+)

| Category          | Entities                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------- |
| Identity          | Name, Gender, Nationality, Username                                                               |
| Contact           | Email, Phone, Address, Location                                                                   |
| Government ID     | Aadhaar, PAN, Passport, Voter ID, Driving Licence, Ration Card                                    |
| Financial         | Credit Card, CVV, Bank Account, Demat Account, UPI ID, IFSC, MICR Code, Cheque Number, CIF Number |
| Tax & Corporate   | GSTIN, TAN, CIN, SEBI Registration                                                                |
| Employment        | UAN, EPF Member ID, ESIC                                                                          |
| Healthcare        | ABHA Number                                                                                       |
| Transport         | Vehicle Number, FASTag ID                                                                         |
| Loans & Insurance | Loan Account Number, Insurance Policy Number                                                      |
| Network           | IP Address, MAC Address                                                                           |
| Auth              | Password, OAuth Token                                                                             |
| Date              | Birth Date                                                                                        |

## Example usage scenarios

**First run — scan everything in config.toml:**

```bash
./dpdpascanner
```

**Scan only one database on one server:**

```bash
./dpdpascanner --target-host localhost --database hr_db
```

**Scan only one engine, across all its instances:**

```bash
./dpdpascanner --engine mongodb
```

**Force a full, no-sampling scan of one database:**

```bash
./dpdpascanner --database hr_db --piiscanner deepscan
```

**Quick scan using column names only, no data read at all:**

```bash
./dpdpascanner --piiscanner metascan --database sales_db
```

**Skip audit and temp tables:**

```bash
./dpdpascanner --exclude-table audit_logs,temp_sessions,migrations
```

**Scan only specific tables:**

```bash
./dpdpascanner --include-table users,customers,employees
```

**See all confidence levels, not just high:**

```bash
./dpdpascanner --print-all --database hr_db
```

**Scan with a Postgres connection URI, no config.toml:**

```bash
./dpdpascanner "postgres://postgres:password@localhost:5432/hr_db?sslmode=disable"
```

**Re-run later and only pick up what's changed:**

```bash
./dpdpascanner --incremental
```

**Start incremental tracking over from scratch:**

```bash
./dpdpascanner --reset-incremental
```

**Non-default schema:**

```bash
./dpdpascanner --schema hr --database company_db
```

**Just the short version, no big tables printed:**

```bash
./dpdpascanner --print-summary --database hr_db
```


