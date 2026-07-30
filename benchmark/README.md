# Benchmark & Demo Database

## Running the Benchmark

Generate test data and run accuracy benchmark:

```bash
python3 benchmark/gen_india_benchmark.py
cd benchmark && go run benchmark_runner.go
```

Expected: ~99.98% accuracy across 28 India entities.

## Setting Up the Demo Database

The demo database (`pii_demo`) is used for live database scanning tests.

### 1. Create the database

```bash
psql -U postgres -c "CREATE DATABASE pii_demo;"
psql -U postgres -d pii_demo -f benchmark/demo_schema.sql
```

### 2. Populate with test data

```bash
pip3 install psycopg2-binary faker
python3 benchmark/gen_demo_db.py 10000
```

This generates 10,000 rows per table with realistic Indian PII data.

### 3. Run the scanner

```bash
go build -o dpdpscanner ./cmd/dpdpscanner/
echo "" | ./dpdpscanner --config . --piiscanner datascan --database pii_demo
```

Or use the web UI:

```bash
go run cmd/server/main.go
```

Then open http://localhost:8080

## Tables in pii_demo

| Table | Purpose |
|-------|---------|
| customers_clean | Named columns — baseline detection |
| legacy_records | Obscure column names — value detection only |
| global_employees | Mixed India/US data |
| bank_transactions | GSTIN, IFSC heavy |
| product_catalog | No PII — negative control |
