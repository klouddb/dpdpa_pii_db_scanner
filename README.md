# DPDPAScanner — India DPDP Act PII Scanner

[![Go Build](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/release.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/release.yml) [![Go Lint](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/golangci.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/golangci.yml) [![Golang Vulnerability Check](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/klouddb/dpdpa_pii_db_scanner/actions/workflows/govulncheck.yml)

# DPDPA PII Scanner for PostgreSQL

A command-line **PII (Personally Identifiable Information) scanner** for PostgreSQL databases, built for compliance with **India's Digital Personal Data Protection (DPDP) Act**.

### Important Note 
Use this together with KloudDB Shield (https://github.com/klouddb/klouddbshield) to strengthen your PostgreSQL security posture 

## What It Does

Point it at one or more PostgreSQL servers, and it scans **every table** for sensitive data, including:
| **Category**          | **Entities**                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| **Identity**          | Name, Gender, Nationality, Username                                                               |
| **Contact**           | Email, Phone, Address, Location                                                                   |
| **Government ID**     | Aadhaar, PAN, Passport, Voter ID, Driving Licence, Ration Card                                    |
| **Financial**         | Credit Card, CVV, Bank Account, Demat Account, UPI ID, IFSC, MICR Code, Cheque Number, CIF Number |
| **Tax & Corporate**   | GSTIN, TAN, CIN, SEBI Registration                                                                |
| **Employment**        | UAN, EPF Member ID, ESIC                                                                          |
| **Healthcare**        | ABHA Number                                                                                       |
| **Transport**         | Vehicle Number, FASTag ID                                                                         |
| **Loans & Insurance** | Loan Account Number, Insurance Policy Number                                                      |
| **Network**           | IP Address, MAC Address                                                                           |
| **Authentication**    | Password, OAuth Token                                                                             |
| **Date**              | Birth Date                                                                                        |

## Output Formats

Results are delivered three ways:

| Format | Description |
|--------|-------------|
| 🖥️ **Terminal** | Instant results right in your console |
| 📄 **Log Files** | Persistent logs for audits and records |
| 🌐 **HTML Report** | A self-contained report you can open in any browser |

## Install and Configure

## Installation

### Method 1: Install from Pre-built Packages (Recommended)

Download the appropriate package for your operating system from the [Releases](https://github.com/klouddb/dpdpa_pii_db_scanner/releases/) page and install it using your system's package manager.

**CentOS / RHEL / Fedora:**
```bash
sudo rpm -i dpdpa_pii_db_scanner-<version>.rpm
```

**Ubuntu / Debian:**
```bash
sudo dpkg -i dpdpa_pii_db_scanner-<version>.deb
```

### Method 2: Build from Source

Ensure you have [Go](https://go.dev/dl/) installed, then run:

```bash
git clone https://github.com/klouddb/dpdpa_pii_db_scanner.git
cd dpdpa_pii_db_scanner
go build -o dpdpascanner ./cmd/
```

This will produce a `dpdpascanner` binary in the current directory.
##  Run a Scan


### Run without config.toml

Pass a PostgreSQL connection URI as the first argument — no need to edit `dbname` in a config file each time:

```bash
dpdpascanner postgres://user:pass@localhost:5432/mydb?sslmode=disable
```

Always make sure your connection is secure when connecting to a database over a network you don't fully trust. Prefer SSH, a VPN, or `sslmode=verify-full`. If your connection doesn't use SSL, append `?sslmode=disable` (local development only).

Other flags still work with a URI (`--piiscanner`, `--schema`, `--include-table`, `--print-all`, etc.). Do not combine a URI with `--config`, `--database`, or `--target-host`.

**Scan a specific database (from config.toml):**
```bash
dpdpascanner -database sales_db
```

**config file:**

Once you install package you need to setup config.toml under /etc/dpdpscanner

```
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password_here"
databases = ["my_database"]
```
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

## All Available Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | current folder | Folder containing `config.toml`. Use this if your config file lives somewhere else, e.g. `--config C:\configs\prod`. Not used with a `postgres://` URI. |
| `--piiscanner` | *(not set — see below)* | Force one scan type for every table. Options: `datascan`, `metascan`, `deepscan`. Leave this flag out entirely to get the recommended automatic behavior — see "Default Behavior (no `--piiscanner` flag)" below. |
| `--database` | *(all databases)* | Scan only this one database from config.toml. Not used with a `postgres://` URI. |
| `--schema` | `public` | PostgreSQL schema to scan. Most databases only use `public`. |
| `--target-host` | *(all hosts)* | Scan only the server with this hostname. Leave empty to scan every server in the config. Not used with a `postgres://` URI. |
| `--exclude-table` | *(none)* | Comma-separated list of tables to skip. Example: `--exclude-table audit_logs,temp_data` |
| `--include-table` | *(all tables)* | Comma-separated list of tables to scan. Every other table is skipped. |
| `--print-all` | `false` | By default only High-confidence findings appear in the terminal, log files, and HTML report. Add this flag to also include Medium and Low confidence results. |
| `--print-summary` | `false` | Print a short, condensed summary instead of the full results table. |
| `--no-timeout` | `false` | To disable timeout after 5 minutes. Useful when running deepscan on large database |
---
