"""
Comprehensive PII seeder — covers all 32 India entities from gen_india_benchmark.py
10k rows per table, edge-case variants per entity type.
Database: pii_comprehensive (created automatically if missing)
"""

import random, string, psycopg2
from psycopg2.extras import execute_values

random.seed(2025)
N = 10_000
BATCH = 2000

DB = {
    "host":     "localhost",
    "port":     5432,
    "user":     "postgres",
    "password": "9849",   # ← change if needed
}

# ── Checksum helpers ─────────────────────────────────────────────────────────

VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
              [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
              [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
              [9,8,7,6,5,4,3,2,1,0]]
VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
              [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
              [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

def verhoeff_check_digit(num):
    inv = [0,4,3,2,1,9,8,7,6,5]; c = 0
    for i, d in enumerate(reversed(num)):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][int(d)]]
    return str(inv[c])

def luhn_digit(s):
    d = [int(c) for c in s]; t, p = 0, (len(d) + 1) % 2
    for i, x in enumerate(d):
        if i % 2 == p: x *= 2; x -= 9 if x > 9 else 0
        t += x
    return str((10 - t % 10) % 10)

def gstin_check(s14):
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cm = {c: i for i, c in enumerate(chars)}; total = 0
    for i, c in enumerate(s14.upper()):
        v = cm[c]; total += v if i % 2 == 0 else (v * 2) // 36 + (v * 2) % 36
    return chars[(36 - total % 36) % 36]

# ── Base generators (all 32 entities) ────────────────────────────────────────

STATES = ['AP','AR','AS','BR','CG','CH','DL','GA','GJ','HP','HR','JH','JK',
          'KA','KL','LA','MH','ML','MN','MP','MZ','NL','OD','PB','PY','RJ',
          'SK','TN','TR','TS','UK','UP','WB','AN','DD','DN']

def gen_aadhaar():
    base = str(random.randint(2, 9)) + ''.join(random.choices('0123456789', k=10))
    return base + verhoeff_check_digit(base)

def gen_pan():
    L = string.ascii_uppercase
    return (''.join(random.choices(L, k=3)) + random.choice('PCFHBGJLPT')
            + random.choice(L) + ''.join(random.choices('0123456789', k=4))
            + random.choice(L))

def gen_passport():
    return random.choice('ABCDEFGHJKNPRSTUVWYZ') + str(random.randint(1000000, 9999999))

def gen_voter():
    return ''.join(random.choices(string.ascii_uppercase, k=3)) + ''.join(random.choices('0123456789', k=7))

def gen_dl():
    state = random.choice(STATES)
    return f"{state}{random.randint(1,99):02d}{random.randint(1990,2023)}{random.randint(1000000,9999999)}"

def gen_vehicle():
    state = random.choice(STATES)
    letters = ''.join(random.choices(string.ascii_uppercase, k=random.choice([1, 2])))
    return f"{state}{random.randint(1,99):02d}{letters}{random.randint(1,9999):04d}"

def gen_phone():
    return str(random.randint(6, 9)) + ''.join(random.choices('0123456789', k=9))

def gen_email():
    names = ['rahul','priya','amit','sara','raj','neha','vijay','kavya','suresh','pooja',
             'arjun','deepa','ravi','anita','sanjay','meera','vikram','sunita','kiran','mohan']
    domains = ['gmail.com','yahoo.com','hotmail.com','outlook.com','rediffmail.com',
               'company.in','work.co.in','mail.com','protonmail.com','icloud.com']
    sep = random.choice(['', '.', '_', ''])
    return f"{random.choice(names)}{sep}{random.randint(1,9999)}@{random.choice(domains)}"

def gen_gstin():
    state = f"{random.randint(1,37):02d}"
    pan = gen_pan()
    entity = random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    partial = state + pan + entity + 'Z'
    return partial + gstin_check(partial)

def gen_ifsc():
    banks = ['SBIN','HDFC','ICIC','AXIS','PUNB','UBIN','BKID','CNRB','IOBA','VIJB',
             'KKBK','BARB','INDB','YESB','IDFB','FDRL','LAVB','SRCB','MAHB','CBIN']
    return random.choice(banks) + '0' + ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=6))

def gen_bank():
    return ''.join(random.choices('0123456789', k=random.choice([9, 11, 14, 15, 17, 18])))

def gen_card():
    networks = [('4', 16), ('51', 16), ('52', 16), ('53', 16), ('54', 16), ('55', 16),
                ('34', 15), ('37', 15), ('6011', 16), ('65', 16), ('2221', 16),
                ('60', 16), ('81', 16)]
    prefix, length = random.choice(networks)
    body = prefix + ''.join(random.choices('0123456789', k=length - 1 - len(prefix)))
    return body + luhn_digit(body)

def gen_demat():
    return 'IN' + ''.join(random.choices('0123456789', k=14))

def gen_cheque():
    return ''.join(random.choices('0123456789', k=6))

def gen_cif():
    return ''.join(random.choices('0123456789', k=random.randint(8, 11)))

def gen_loan():
    return ''.join(random.choices(string.ascii_uppercase, k=2)) + ''.join(random.choices('0123456789', k=random.randint(8, 18)))

def gen_insurance():
    prefixes = ['LIC','SBI','MAX','HDG','ICL','BAJ','REL','KOT','NIA','UII']
    return random.choice(prefixes) + ''.join(random.choices('0123456789', k=random.randint(8, 15)))

def gen_fastag():
    return ''.join(random.choices(string.ascii_uppercase + '0123456789', k=random.randint(10, 20)))

UPI_HANDLES = [
    'ybl','ibl','axl','okaxis','okhdfcbank','okicici','oksbi','paytm',
    'ptsbi','pthdfc','ptaxis','apl','rapl','yapl','waaxis','waicici',
    'wahdfcbank','wasbi','yesg','yescred','superyes','ikwik','fkaxis',
    'indie','federal','fifederal','icici','axisb','hsbc','idbi',
    'indianbank','kotak','kotak811','barodampay','pnb','unionbank',
    'canara','bob','sbi','hdfcbank','icicibank','axisbank','idfcfirst',
    'idfc','rbl','bandhan','yesbank','indusind','au','aubank','equitas',
    'airtel','freecharge','slice','cred','groww','jupiter','mobikwik',
    'amazonpay','flipkart','phonepe','gpay','bhim'
]

def gen_upi():
    first = ['rahul','priya','amit','sneha','vikram','anjali','ravi','neha','sanjay','pooja','arjun','deepa']
    last  = ['sharma','patel','kumar','singh','gupta','reddy','nair','mehta','joshi','verma']
    fmt = random.randint(0, 4)
    if fmt == 0:   u = random.choice(first) + '.' + random.choice(last)
    elif fmt == 1: u = random.choice('6789') + ''.join(random.choices('0123456789', k=9))
    elif fmt == 2: u = random.choice(first) + str(random.randint(1, 9999))
    elif fmt == 3: u = random.choice(first) + '_' + random.choice(last)
    else:          u = random.choice(first) + random.choice(last)
    return u + '@' + random.choice(UPI_HANDLES)

def gen_cvv():
    return str(random.randint(100, 999)) if random.random() < 0.85 else str(random.randint(1000, 9999))

def gen_tan():
    return (''.join(random.choices(string.ascii_uppercase, k=3))
            + random.choice(string.ascii_uppercase)
            + ''.join(random.choices('0123456789', k=5))
            + random.choice(string.ascii_uppercase))

def gen_cin():
    states_cin = ['MH','DL','KA','TN','GJ','UP','WB','RJ','AP','KL','MP','HR','TS','OD','PB']
    ctypes = ['PLC','PVT','LLP','OPC','SGC','NPL']
    return (random.choice('LU') + f"{random.randint(10000,99999)}"
            + random.choice(states_cin) + f"{random.randint(1956,2024)}"
            + random.choice(ctypes) + f"{random.randint(100000,999999)}")

def gen_micr():
    return f"{random.randint(100,799):03d}{random.randint(1,999):03d}{random.randint(1,999):03d}"

def gen_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def gen_mac():
    return ':'.join(f'{random.randint(0,255):02X}' for _ in range(6))

def gen_abha():
    return (f"{random.randint(10,99)}-{random.randint(1000,9999)}"
            f"-{random.randint(1000,9999)}-{random.randint(1000,9999)}")

def gen_uan():
    return str(random.randint(100000000000, 999999999999))

def gen_epf():
    office = ''.join(random.choices(string.ascii_uppercase, k=3))
    return (random.choice(STATES) + office
            + f"{random.randint(0,9999999):07d}{random.randint(1,9999999999):010d}")

def gen_esic():
    return (f"{random.randint(10,99)}-{random.randint(10,99)}"
            f"-{random.randint(100000,999999)}-{random.randint(100,999)}-{random.randint(1000,9999)}")

def gen_ration():
    s = ['MH','DL','KA','TN','GJ','UP','WB','RJ','AP','KL','MP','HR']
    return random.choice(s) + '-' + ''.join(random.choices('0123456789', k=random.randint(10, 13)))

def gen_sebi():
    return random.choice(['INZ','INH','INP','INR','INA','INM','INQ']) + ''.join(random.choices('0123456789', k=9))

def gen_dob():
    d, m, y = random.randint(1,28), random.randint(1,12), random.randint(1940,2005)
    fmt = random.choice([
        f"{d:02d}/{m:02d}/{y}", f"{d:02d}-{m:02d}-{y}",
        f"{y}-{m:02d}-{d:02d}", f"{d:02d}.{m:02d}.{y}",
    ])
    return fmt

def gen_location():
    return f"{round(random.uniform(8.0,37.0),4)}, {round(random.uniform(68.0,97.0),4)}"

# ── Edge-case format variants ─────────────────────────────────────────────────

def gen_aadhaar_spaced():
    a = gen_aadhaar()
    return f"{a[:4]} {a[4:8]} {a[8:]}"

def gen_aadhaar_dashed():
    a = gen_aadhaar()
    return f"{a[:4]}-{a[4:8]}-{a[8:]}"

def gen_aadhaar_masked():
    a = gen_aadhaar()
    return f"XXXX-XXXX-{a[8:]}"

def gen_phone_plus91():
    return "+91" + gen_phone()

def gen_phone_91():
    return "91" + gen_phone()

def gen_phone_zero():
    return "0" + gen_phone()

def gen_email_dots():
    names = ['rahul.kumar','priya.sharma','amit.patel','sneha.gupta','ravi.verma']
    domains = ['gmail.com','yahoo.co.in','outlook.com','company.in','rediffmail.com']
    return f"{random.choice(names)}{random.randint(1,99)}@{random.choice(domains)}"

def gen_email_plus():
    names = ['rahul','priya','amit','sara','raj']
    domains = ['gmail.com','outlook.com']
    return f"{random.choice(names)}+{random.randint(1,999)}@{random.choice(domains)}"

def gen_dob_ddmmyy():
    d, m, y = random.randint(1,28), random.randint(1,12), random.randint(1940,2005)
    return f"{d:02d}/{m:02d}/{str(y)[2:]}"

def gen_dob_monthname():
    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    d, m, y = random.randint(1,28), random.randint(0,11), random.randint(1940,2005)
    return f"{d:02d} {months[m]} {y}"

def gen_card_spaced():
    c = gen_card()
    if len(c) == 16:
        return f"{c[:4]} {c[4:8]} {c[8:12]} {c[12:]}"
    return f"{c[:4]} {c[4:10]} {c[10:]}"

def gen_card_dashed():
    c = gen_card()
    if len(c) == 16:
        return f"{c[:4]}-{c[4:8]}-{c[8:12]}-{c[12:]}"
    return c

def gen_mac_hyphen():
    return '-'.join(f'{random.randint(0,255):02X}' for _ in range(6))

def gen_mac_plain():
    return ''.join(f'{random.randint(0,255):02X}' for _ in range(6))

def gen_ip_with_port():
    return gen_ip() + f":{random.choice([80,443,8080,3306,5432,22,8443])}"

def gen_neg():
    choices = [
        lambda: str(random.randint(10000000, 99999999)),
        lambda: ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(6, 12))),
        lambda: f"ORD{random.randint(100000, 999999)}",
        lambda: f"INV{random.randint(10000, 99999)}",
        lambda: f"REF-{random.randint(1000000, 9999999)}",
        lambda: f"SKU-{random.randint(1000, 9999)}-{''.join(random.choices(string.ascii_uppercase, k=3))}",
        lambda: ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=random.randint(8, 20))),
    ]
    return random.choice(choices)()

# ── DB setup ──────────────────────────────────────────────────────────────────

def create_db():
    conn = psycopg2.connect(**DB, dbname="postgres")
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname='pii_comprehensive'")
    if not cur.fetchone():
        cur.execute("CREATE DATABASE pii_comprehensive")
        print("Created database: pii_comprehensive")
    cur.close(); conn.close()

def get_conn():
    return psycopg2.connect(**DB, dbname="pii_comprehensive")

def seed(cur, conn, table, cols_def, col_names, gen_row_fn):
    cols_str = ", ".join(f"{c} TEXT" for c in cols_def)
    cur.execute(f"DROP TABLE IF EXISTS {table};")
    cur.execute(f"CREATE TABLE {table} (id SERIAL PRIMARY KEY, {cols_str});")
    conn.commit()
    print(f"  Table {table}: inserting {N} rows…", end="", flush=True)
    buf = []
    for _ in range(N):
        buf.append(gen_row_fn())
        if len(buf) >= BATCH:
            execute_values(cur, f"INSERT INTO {table} ({','.join(col_names)}) VALUES %s", buf)
            conn.commit(); buf = []
    if buf:
        execute_values(cur, f"INSERT INTO {table} ({','.join(col_names)}) VALUES %s", buf)
        conn.commit()
    print(" done")

# ── Table definitions ─────────────────────────────────────────────────────────

def main():
    create_db()
    conn = get_conn()
    cur  = conn.cursor()

    print(f"\nSeeding pii_comprehensive — {N} rows per table\n")

    # ── 1. identity_primary: Aadhaar (3 formats) + PAN + Passport + Voter ────
    seed(cur, conn, "identity_primary",
        ["aadhaar_raw","aadhaar_spaced","aadhaar_dashed","pan_number","passport_number","voter_id"],
        ["aadhaar_raw","aadhaar_spaced","aadhaar_dashed","pan_number","passport_number","voter_id"],
        lambda: (gen_aadhaar(), gen_aadhaar_spaced(), gen_aadhaar_dashed(),
                 gen_pan(), gen_passport(), gen_voter()))

    # ── 2. identity_secondary: DL + Vehicle + Ration + masked Aadhaar ────────
    seed(cur, conn, "identity_secondary",
        ["driving_licence","vehicle_number","ration_card","aadhaar_masked","abha_number"],
        ["driving_licence","vehicle_number","ration_card","aadhaar_masked","abha_number"],
        lambda: (gen_dl(), gen_vehicle(), gen_ration(), gen_aadhaar_masked(), gen_abha()))

    # ── 3. contact_info: email (4 variants) + phone (4 variants) + DOB (5 formats) + location ──
    seed(cur, conn, "contact_info",
        ["email_basic","email_dots","email_plus","phone_plain","phone_plus91",
         "phone_zero","dob_standard","dob_short","dob_monthname","geo_location"],
        ["email_basic","email_dots","email_plus","phone_plain","phone_plus91",
         "phone_zero","dob_standard","dob_short","dob_monthname","geo_location"],
        lambda: (gen_email(), gen_email_dots(), gen_email_plus(),
                 gen_phone(), gen_phone_plus91(), gen_phone_zero(),
                 gen_dob(), gen_dob_ddmmyy(), gen_dob_monthname(), gen_location()))

    # ── 4. network_info: IP (raw + with port) + MAC (3 formats) ─────────────
    seed(cur, conn, "network_info",
        ["ip_address","ip_with_port","mac_colon","mac_hyphen","mac_plain"],
        ["ip_address","ip_with_port","mac_colon","mac_hyphen","mac_plain"],
        lambda: (gen_ip(), gen_ip_with_port(), gen_mac(), gen_mac_hyphen(), gen_mac_plain()))

    # ── 5. payment_cards: all card networks, spaced/dashed, CVV ─────────────
    seed(cur, conn, "payment_cards",
        ["credit_card_raw","credit_card_spaced","credit_card_dashed","cvv_3digit","cvv_4digit"],
        ["credit_card_raw","credit_card_spaced","credit_card_dashed","cvv_3digit","cvv_4digit"],
        lambda: (gen_card(), gen_card_spaced(), gen_card_dashed(),
                 str(random.randint(100,999)), str(random.randint(1000,9999))))

    # ── 6. banking_info: bank account (all lengths) + IFSC + MICR + cheque + CIF + demat ──
    seed(cur, conn, "banking_info",
        ["bank_account","ifsc_code","micr_code","cheque_number","cif_number","demat_account"],
        ["bank_account","ifsc_code","micr_code","cheque_number","cif_number","demat_account"],
        lambda: (gen_bank(), gen_ifsc(), gen_micr(), gen_cheque(), gen_cif(), gen_demat()))

    # ── 7. corporate_compliance: GSTIN (all 37 states) + TAN + CIN + SEBI ───
    seed(cur, conn, "corporate_compliance",
        ["gstin","tan_number","cin_number","sebi_reg"],
        ["gstin","tan_number","cin_number","sebi_reg"],
        lambda: (gen_gstin(), gen_tan(), gen_cin(), gen_sebi()))

    # ── 8. loan_insurance: loan + insurance + FASTag + UPI (all handles) ─────
    seed(cur, conn, "loan_insurance",
        ["loan_account","insurance_policy","fastag_id","upi_id"],
        ["loan_account","insurance_policy","fastag_id","upi_id"],
        lambda: (gen_loan(), gen_insurance(), gen_fastag(), gen_upi()))

    # ── 9. social_welfare: UAN + EPF + ESIC ──────────────────────────────────
    seed(cur, conn, "social_welfare",
        ["uan_number","epf_member_id","esic_number"],
        ["uan_number","epf_member_id","esic_number"],
        lambda: (gen_uan(), gen_epf(), gen_esic()))

    # ── 10. obfuscated_pii: all PII in field_N column names (data scan test) ─
    seed(cur, conn, "obfuscated_pii",
        ["field_01","field_02","field_03","field_04","field_05","field_06",
         "field_07","field_08","field_09","field_10","field_11","field_12"],
        ["field_01","field_02","field_03","field_04","field_05","field_06",
         "field_07","field_08","field_09","field_10","field_11","field_12"],
        lambda: (gen_aadhaar(), gen_pan(), gen_passport(), gen_voter(),
                 gen_phone(), gen_email(), gen_gstin(), gen_card(),
                 gen_ifsc(), gen_bank(), gen_upi(), gen_dl()))

    # ── 11. mixed_pii_noise: 40% real PII, 60% noise (low-confidence test) ──
    def mixed_row():
        pick = lambda real, _: real() if random.random() < 0.4 else gen_neg()
        return (
            pick(gen_aadhaar, None), pick(gen_pan, None),
            pick(gen_phone, None),   pick(gen_email, None),
            pick(gen_gstin, None),   pick(gen_card, None),
            gen_neg(), gen_neg()
        )
    seed(cur, conn, "mixed_pii_noise",
        ["val_a","val_b","val_c","val_d","val_e","val_f","noise_1","noise_2"],
        ["val_a","val_b","val_c","val_d","val_e","val_f","noise_1","noise_2"],
        mixed_row)

    # ── 12. no_pii_control: zero PII (negative control) ─────────────────────
    products = ['Laptop','Mouse','Keyboard','Monitor','Headphones','Webcam','Desk','Chair']
    categories = ['Electronics','Furniture','Accessories','Office','Peripherals']
    seed(cur, conn, "no_pii_control",
        ["product_name","sku","category","order_ref","notes"],
        ["product_name","sku","category","order_ref","notes"],
        lambda: (
            random.choice(products),
            f"SKU-{random.randint(1000,9999)}-{''.join(random.choices(string.ascii_uppercase,k=3))}",
            random.choice(categories),
            f"ORD-{random.randint(100000,999999)}",
            f"Standard product note {random.randint(1,9999)}"
        ))

    # ── 13. legacy_mixed: obscure col names, mix of India + noise ─────────────
    seed(cur, conn, "legacy_mixed",
        ["ref_a","ref_b","ref_c","ref_d","ref_e","ref_f","ref_g","ref_h"],
        ["ref_a","ref_b","ref_c","ref_d","ref_e","ref_f","ref_g","ref_h"],
        lambda: (
            gen_aadhaar_spaced(), gen_pan(), gen_gstin(), gen_phone_plus91(),
            gen_email_dots(), gen_card_spaced(), gen_upi(), gen_dob_monthname()
        ))

    cur.close(); conn.close()
    print(f"\nDone! All tables in pii_comprehensive seeded with {N} rows each.")
    print("Tables created:")
    print("  1. identity_primary     — Aadhaar (raw/spaced/dashed), PAN, Passport, Voter")
    print("  2. identity_secondary   — DL, Vehicle, Ration card, Aadhaar masked, ABHA")
    print("  3. contact_info         — Email (3 formats), Phone (3 formats), DOB (3 formats), Location")
    print("  4. network_info         — IP (raw/with port), MAC (colon/hyphen/plain)")
    print("  5. payment_cards        — Credit cards (all networks + spaced/dashed), CVV 3+4 digit")
    print("  6. banking_info         — Bank account, IFSC, MICR, Cheque, CIF, Demat")
    print("  7. corporate_compliance — GSTIN (all 37 states), TAN, CIN, SEBI")
    print("  8. loan_insurance       — Loan, Insurance, FASTag, UPI (60+ handles)")
    print("  9. social_welfare       — UAN, EPF, ESIC")
    print(" 10. obfuscated_pii       — All PII in field_N columns (tests data scan)")
    print(" 11. mixed_pii_noise      — 40% real PII + 60% noise (low-confidence test)")
    print(" 12. no_pii_control       — Zero PII (negative control)")
    print(" 13. legacy_mixed         — Obscure col names, mixed India PII")

if __name__ == "__main__":
    main()
