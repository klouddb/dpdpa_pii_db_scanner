-- Scenario 1: Clean naming (column names hint at PII)
CREATE TABLE customers_clean (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    email VARCHAR(100),
    aadhaar_number VARCHAR(20),
    pan_number VARCHAR(20),
    mobile_number VARCHAR(20),
    bank_account_number VARCHAR(20),
    ifsc_code VARCHAR(15),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Scenario 2: Obscure naming (column names give NO hint) — the killer demo
CREATE TABLE legacy_records (
    id SERIAL PRIMARY KEY,
    field_12 VARCHAR(100),
    field_23 VARCHAR(100),
    field_47 VARCHAR(20),
    ref_code VARCHAR(20),
    serial_val VARCHAR(20),
    identifier VARCHAR(20),
    data_point VARCHAR(20),
    misc_value VARCHAR(20),
    notes TEXT
);

-- Scenario 3: Mixed India/US (multinational company)
CREATE TABLE global_employees (
    id SERIAL PRIMARY KEY,
    employee_name VARCHAR(100),
    work_email VARCHAR(100),
    country VARCHAR(50),
    india_aadhaar VARCHAR(20),
    india_pan VARCHAR(20),
    us_ssn VARCHAR(20),
    us_itin VARCHAR(20),
    phone VARCHAR(20),
    salary NUMERIC(10,2)
);

-- Scenario 4: GSTIN/IFSC heavy (financial/banking table)
CREATE TABLE bank_transactions (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(30),
    sender_account VARCHAR(20),
    sender_ifsc VARCHAR(15),
    receiver_account VARCHAR(20),
    receiver_ifsc VARCHAR(15),
    company_gstin VARCHAR(20),
    amount NUMERIC(12,2),
    transaction_date TIMESTAMP
);

-- Scenario 5: No PII at all (negative control)
CREATE TABLE product_catalog (
    id SERIAL PRIMARY KEY,
    product_name VARCHAR(100),
    sku VARCHAR(30),
    category VARCHAR(50),
    price NUMERIC(10,2),
    stock_quantity INT,
    last_updated TIMESTAMP
);
