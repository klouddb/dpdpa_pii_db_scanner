# dpdpascanner — India DPDP Act PII Scanner

[![Go Build](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/release.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/release.yml) [![Go Lint](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/golangci.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/golangci.yml) [![Golang Vulnerability Check](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/govulncheck.yml)

A command-line PII (Personally Identifiable Information) scanner for PostgreSQL databases, built for compliance with India's **Digital Personal Data Protection (DPDP) Act 2023**.

Point it at one or more PostgreSQL servers and it will scan every table for sensitive data — Aadhaar, PAN, GSTIN, bank accounts, credit cards, passports, UPI IDs, driving licences, and **40+ more entity types** — and give you the results in your terminal, in log files, and in a self-contained HTML report you can open in a browser.

You don't need to know Go or SQL to use this tool. Just follow the steps below in order.

---

## What You Get

After every scan you get:

- **Terminal output** — a clean summary showing High-confidence findings for the databases you scanned
- **HTML report** — `kshield_pii_report.html` — a visual report with tabs for High and Low/Medium confidence findings, pagination, and colour-coded labels. Open it by double-clicking the file. 
- **Log files** — `kshield_pii_highconfidence.log` and `kshield_pii_lowconfidence.log` — the full, unabridged results for every confidence level
- **Multi-instance support** — scan multiple PostgreSQL servers and multiple databases per server in a single run

> **Note:** The HTML report (and both log files) are overwritten every time a scan runs. If your config scans multiple databases in one run, the report will only contain the **last** database scanned. Use `--database yourdb` to scan one database at a time and keep a separate report per database.

The scanner works two ways at once on every table:

- **Meta Scan** — looks at column names only (e.g. a column called `aadhaar_number`), no data is read
- **Data Scan** — reads the actual values stored in each column and checks them against 40+ pattern-matching rules

---

## Prerequisites

| Tool | Why | Version |
|------|-----|---------|
| Go | To build the scanner | 1.18 or newer |
| PostgreSQL | The database you want to scan | Any modern version |
| Git | To download this repo | Any |
| Python 3 *(optional)* | Only needed if you want to seed a test database with fake data | 3.8 or newer |

You do **not** need Python to run the scanner itself — it's only used for the optional test-data script.

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/klouddb/dpdpa_pii_db_scanner.git
cd DPA_private
```

---

## Step 2 — Create the Config File

Create a file named `config.toml` in the project root (the same folder as this README). This tells the scanner which PostgreSQL servers and databases to look at, and what credentials to use.

**Basic example — one server, one database:**
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password_here"
databases = ["my_database"]
sslmode   = "disable" # local development only
```

**Advanced example — multiple servers and databases:**
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "password1"
databases = ["sales_db", "hr_db", "finance_db"]
sslmode   = "disable" # local development only

[[instances]]
host      = "prod-server.example.com"
port      = 5432
user      = "readonly_user"
password  = "password2"
databases = ["production_db"]
sslmode   = "verify-full"
sslrootcert = "/etc/dpdpscanner/certs/root.crt"
# sslcert = "/etc/dpdpscanner/certs/client.crt"
# sslkey = "/etc/dpdpscanner/certs/client.key"
```

> `config.toml` is listed in `.gitignore`, so it will **not** be accidentally committed or pushed to GitHub. Your passwords stay local.
>
> TLS defaults to `require` when `sslmode` is omitted. Use `verify-full` with
> `sslrootcert` for production servers. Set `disable` only for trusted local
> development databases that do not support TLS.

---

## Step 3 — Build the Binary

```bash
# On Linux / Mac
go build -o dpdpascanner ./cmd/

# On Windows
go build -o dpdpascanner.exe ./cmd/
```

This creates a single `dpdpascanner` (or `dpdpascanner.exe` on Windows) file in the project folder. This is the program you'll actually run — you only need to build it once (rebuild only if the code changes).

---

## Step 4 — Run a Scan

**Scan everything in config.toml (simplest — just do this first):**
```bash
# Linux / Mac
./dpdpascanner

# Windows
.\dpdpascanner.exe
```

> **Windows users:** always type the full `.exe` name, e.g. `.\dpdpascanner.exe`, not just `dpdpascanner`.

**Scan a specific database:**
```bash
./dpdpascanner --database sales_db
```

**Scan a specific server (all its databases):**
```bash
./dpdpascanner --target-host prod-server.example.com
```

**Scan a specific server and database together:**
```bash
./dpdpascanner --target-host localhost --database hr_db
```

The first time you run a scan, just use the plain `./dpdpascanner` command with no flags — leaving out `--piiscanner` entirely gives you the best default behavior (see "Default Behavior" below). Add `--piiscanner` later only if you specifically want to force one scan type everywhere.

---

## All Available Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | current folder | Folder containing `config.toml`. Use this if your config file lives somewhere else, e.g. `--config C:\configs\prod`. |
| `--piiscanner` | *(not set — see below)* | Force one scan type for every table. Options: `datascan`, `metascan`, `deepscan`. Leave this flag out entirely to get the recommended automatic behavior — see "Default Behavior (no `--piiscanner` flag)" below. |
| `--database` | *(all databases)* | Scan only this one database. Leave empty to scan every database listed in the config. |
| `--schema` | `public` | PostgreSQL schema to scan. Most databases only use `public`. |
| `--target-host` | *(all hosts)* | Scan only the server with this hostname. Leave empty to scan every server in the config. |
| `--exclude-table` | *(none)* | Comma-separated list of tables to skip. Example: `--exclude-table audit_logs,temp_data` |
| `--include-table` | *(all tables)* | Comma-separated list of tables to scan. Every other table is skipped. |
| `--print-all` | `false` | By default the terminal only shows High-confidence findings. Add this flag to also print Medium and Low confidence findings. |
| `--print-summary` | `false` | Print a short, condensed summary instead of the full results table. |
| `--no-timeout` | `false` | To disable timeout after 5 minutes. Useful when running deepscan on large database |
---

## Default Behavior (no `--piiscanner` flag)

This is **not** a scan type you can select — it's simply what happens automatically when you run `./dpdpascanner` without the `--piiscanner` flag, which is the recommended way to run it.

For each table, the scanner checks how many rows it has and picks the best approach on its own:
- **Small tables** (fewer than 10,000 rows) → scanned fully, row by row, so nothing is missed
- **Large tables** (10,000 rows or more) → scanned using the same 10% random sample described under `datascan` below, to keep things fast

You'll see a message like `users has 250 rows - below threshold of 10000 rows, running deep scan` in the terminal while this happens — that's expected, not an error.

- **Best for:** everyday use — you get full accuracy on small tables and speed on big ones without having to decide yourself
- **Output:** Data Scan Report + Meta Scan Report

---

## Scan Types Explained

These are the values you can pass to `--piiscanner` when you want to force the same scan type on every table, instead of the automatic per-table behavior described above.

### `datascan`
Always reads actual data from your database columns, using a random sample — approximately 10% of rows, up to 10,000 rows per table — regardless of table size.

- **Best for:** consistently fast scans across every table, when you're fine with sampling even on small tables
- **How it works:** scans sampled values and matches them against 40+ regex patterns
- **Note:** on small tables (under 10,000 rows) the scanner will print a warning that sampling may miss results, and suggests you omit `--piiscanner` (to get the automatic behavior above) or use `--piiscanner deepscan` instead
- **Output:** Data Scan Report + Meta Scan Report

### `metascan`
Only looks at column names — does **not** read any actual data from the database.

- **Best for:** the fastest possible scan, or environments where you're not allowed to read row data at all
- **How it works:** matches column names against known PII naming patterns
- **Output:** Meta Scan Report only

### `deepscan`
Reads **every row** of every table, no sampling, no limit.

- **Best for:** a thorough, complete scan when you have the time to wait, especially on smaller databases
- **Note:** can be slow on large tables. If a table has more than 100,000 rows, the scanner will pause and ask you to confirm before reading it (`yes` / `no` / `yes to all`), so a huge table can't accidentally lock up your terminal for hours without warning
- **Output:** Data Scan Report + Meta Scan Report

---

## Understanding the Output

### Terminal
While scanning, you'll see progress messages (tables found, scan mode chosen per table, a progress bar for very large tables). Once a database finishes, you get a summary of **High confidence** findings:

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
> Low confidence log file created at: [ /path/to/kshield_pii_lowconfidence.log ]
> HTML report created at: [ /path/to/kshield_pii_report.html ]
```

If nothing was found at all, you'll simply see `> No PII data found in database`.

### HTML Report (`kshield_pii_report.html`)
A self-contained HTML file created in the project folder after each database scan. Just double-click it to open it in your browser — no internet connection needed, nothing is uploaded anywhere.

It contains:
- **Summary cards** — Tables scanned, Data Findings, Meta Findings, Low/Medium confidence Data count, Low/Medium confidence Meta count
- **High Confidence tab** — Data Scan and Meta Scan tables, with pagination for large result sets
- **Low / Medium Confidence tab** — every lower-confidence finding, same table layout
- **Colour-coded labels** — each PII type gets a distinct badge colour (email, phone, password, name/username, address, etc.)
- **Matched ratio bar** — a small visual bar showing what percentage of sampled/scanned values actually matched, for each finding

> **Note:** The HTML report (and both log files) are overwritten every time a scan runs. If your config scans multiple databases in one run, the report will only contain the **last** database scanned. Use `--database yourdb` to scan one database at a time and keep a separate report per database.

### Log Files
Two files are created (or overwritten) after each database scan, in the folder you ran the scanner from:

| File | Contents |
|------|----------|
| `kshield_pii_highconfidence.log` | Every High-confidence finding, full detail |
| `kshield_pii_lowconfidence.log` | Every Medium and Low-confidence finding, full detail |

---

## PII Entities Detected (40 types)

| Category | Entities |
|----------|----------|
| Identity | Name, Gender, Nationality, Username |
| Contact | Email, Phone, Address, Location |
| Government ID | Aadhaar, PAN, Passport, Voter ID, Driving Licence, Ration Card |
| Financial | Credit Card, CVV, Bank Account, Demat Account, UPI ID, IFSC, MICR Code, Cheque Number, CIF Number |
| Tax & Corporate | GSTIN, TAN, CIN, SEBI Registration |
| Employment | UAN, EPF Member ID, ESIC |
| Healthcare | ABHA Number |
| Transport | Vehicle Number, FASTag ID |
| Loans & Insurance | Loan Account Number, Insurance Policy Number |
| Network | IP Address, MAC Address |
| Auth | Password, OAuth Token |
| Date | Birth Date |

---

## Example Usage Scenarios

**Scan everything, all servers and databases (recommended first run):**
```bash
./dpdpascanner
```

**Scan only one database on one server:**
```bash
./dpdpascanner --target-host localhost --database hr_db
```

**Force a full, no-sampling scan of one (smaller) database:**
```bash
./dpdpascanner --database hr_db --piiscanner deepscan
```

**Quick scan using column names only (no data read at all):**
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

**Config file is in a different folder:**
```bash
./dpdpascanner --config C:\configs\prod --database sales_db
```

**See all confidence levels in terminal (not just High):**
```bash
./dpdpascanner --print-all --database hr_db
```

**Non-default schema:**
```bash
./dpdpascanner --schema hr --database company_db
```

**Just want the short version, no big tables:**
```bash
./dpdpascanner --print-summary --database hr_db
```

---

## Project Structure

```
DPA_private/
├── cmd/
│   └── main.go                  ← CLI entry point, all flags defined here
├── piiscanner/
│   ├── detector.go              ← 40 PII label definitions
│   ├── constants.go             ← Scan type constants, ignore rules
│   ├── database_scanner.go      ← Core scan engine (auto/data/deep/meta scan logic)
│   ├── regex_detector.go        ← All the pattern-matching rules
│   ├── output_helper.go         ← Terminal and log file output
│   ├── html_report.go           ← HTML report generator
│   └── ...
├── benchmark/
│   └── seed_comprehensive.py    ← Seeds a test database with all 40 entity types
├── config.toml                  ← Your credentials (not committed to git)
└── go.mod
```

---

## Optional — Seed Test Data

Don't have a database with PII in it yet? Use the seed script to create one full of realistic fake data, so you can try the scanner without touching real data.

```bash
pip install psycopg2-binary
python benchmark/seed_comprehensive.py
```

This creates a `pii_comprehensive` database with several tables, about 10,000 rows each, covering all 40 PII entity types. (Edit the `DB` connection details near the top of `benchmark/seed_comprehensive.py` first if your PostgreSQL user/password isn't the default.)

Then add it to your `config.toml`:
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password"
databases = ["pii_comprehensive"]
```

And run:
```bash
./dpdpascanner --database pii_comprehensive
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Failed to load config.toml` | Make sure `config.toml` exists in the folder you're running the scanner from, or use `--config` to point to its location. On Linux, if no local file is found the scanner also checks `/etc/dpdpscanner/config.toml` before giving up. |
| `Could not connect` | Check that PostgreSQL is running, and that the host, port, user, and password in `config.toml` are correct. |
| `go: command not found` | Go is not installed or not on your system PATH — [install Go](https://go.dev/dl/). |
| Scan takes a long time | Use `--piiscanner metascan` for the fastest possible scan, or `--include-table` to scan only specific tables. |
| Scanner is asking `Do you want to continue? (yes=Y \| no=N \| yes to all=A)` | This only appears during `deepscan` on a table with more than 100,000 rows, so you don't accidentally wait hours without warning. Type `Y` to continue, `N` to skip that table, or `A` to say yes to every large table for the rest of the run. |
| Terminal shows fewer results than the log file | This is expected — the terminal only shows High-confidence findings by default. Full results (including Medium/Low confidence) are always in the log files and the HTML report, or use `--print-all`. |
| HTML report only has the last database | Run with `--database yourdb` to target one database at a time and keep a separate report per database. |
| `[SKIP] Could not connect` for one instance | Other instances in your config still get scanned normally. Fix the credentials for the skipped instance in `config.toml` and re-run. |
| `database "..." not found in config.toml` | The name you passed to `--database` doesn't match any database listed under `databases = [...]` in your `config.toml`. Check spelling. |
