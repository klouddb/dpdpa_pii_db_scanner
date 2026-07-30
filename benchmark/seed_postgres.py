import random, string, psycopg2

random.seed(42)
N = 1000

DB = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "pii_test",
    "user":     "postgres",
    "password": "1234",
}

# ── Generators (copied from gen_india_benchmark.py) ──────────────────────────

VERHOEFF_D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
VERHOEFF_P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

def luhn_digit(s):
    d=[int(c) for c in s]; t,p=0,(len(d)+1)%2
    for i,x in enumerate(d):
        if i%2==p: x*=2; x-=9 if x>9 else 0
        t+=x
    return str((10-t%10)%10)

def verhoeff_valid(num):
    c=0
    for j,d in enumerate(reversed(num)):
        c=VERHOEFF_D[c][VERHOEFF_P[j%8][int(d)]]
    return c==0

def verhoeff_check_digit(num):
    inv=[0,4,3,2,1,9,8,7,6,5]; c=0
    for i,d in enumerate(reversed(num)):
        c=VERHOEFF_D[c][VERHOEFF_P[(i+1)%8][int(d)]]
    return str(inv[c])

def gstin_check(s14):
    chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cm={c:i for i,c in enumerate(chars)}; total=0
    for i,c in enumerate(s14.upper()):
        v=cm[c]; total+= v if i%2==0 else (v*2)//36+(v*2)%36
    return chars[(36-total%36)%36]

STATES=['AP','AR','AS','BR','CG','CH','DL','GA','GJ','HP','HR','JH','JK','KA','KL','LA','MH','ML','MN','MP','MZ','NL','OD','PB','PY','RJ','SK','TN','TR','TS','UK','UP','WB','AN','DD','DN']

def gen_aadhaar():
    base=str(random.randint(2,9))+''.join(random.choices('0123456789',k=10))
    for check in range(10):
        if verhoeff_valid(base+str(check)): return base+str(check)
    return gen_aadhaar()

def gen_pan():
    L=string.ascii_uppercase
    return ''.join(random.choices(L,k=3))+random.choice('PCFHBGJLPT')+random.choice(L)+''.join(random.choices('0123456789',k=4))+random.choice(L)

def gen_passport():
    return random.choice('ABCDEFGHJKNPRSTUVWYZ')+str(random.randint(1000000,9999999))

def gen_voter():
    return ''.join(random.choices(string.ascii_uppercase,k=3))+''.join(random.choices('0123456789',k=7))

def gen_dl():
    state=random.choice(STATES)
    return f"{state}{random.randint(1,99):02d}{random.randint(1990,2023)}{random.randint(1000000,9999999)}"

def gen_vehicle():
    state=random.choice(STATES)
    letters=''.join(random.choices(string.ascii_uppercase,k=random.choice([1,2])))
    return f"{state}{random.randint(1,99):02d}{letters}{random.randint(1,9999):04d}"

def gen_phone():
    return str(random.randint(6,9))+''.join(random.choices('0123456789',k=9))

def gen_email():
    names=['rahul','priya','amit','sara','raj','neha','vijay','kavya','suresh','pooja']
    domains=['gmail.com','yahoo.com','hotmail.com','outlook.com','rediffmail.com']
    return f"{random.choice(names)}{random.randint(1,999)}@{random.choice(domains)}"

def gen_gstin():
    state=f"{random.randint(1,37):02d}"; pan=gen_pan()
    entity=random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    partial=state+pan+entity+'Z'; return partial+gstin_check(partial)

def gen_ifsc():
    banks=['SBIN','HDFC','ICIC','AXIS','PUNB','UBIN','BKID','CNRB','IOBA','VIJB']
    return random.choice(banks)+'0'+''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',k=6))

def gen_bank():
    return ''.join(random.choices('0123456789',k=random.choice([9,11,14,15,17,18])))

def gen_card():
    networks=[('4',16),('52',16),('34',15),('6011',16),('2221',16)]
    prefix,length=random.choice(networks)
    body=prefix+''.join(random.choices('0123456789',k=length-1-len(prefix)))
    return body+luhn_digit(body)

def gen_demat():  return 'IN'+''.join(random.choices('0123456789',k=14))
def gen_cheque(): return ''.join(random.choices('0123456789',k=6))
def gen_cif():    return ''.join(random.choices('0123456789',k=random.randint(8,11)))
def gen_loan():   return ''.join(random.choices(string.ascii_uppercase,k=2))+''.join(random.choices('0123456789',k=random.randint(8,18)))
def gen_insurance(): return random.choice(['LIC','SBI','MAX','HDG','ICL'])+''.join(random.choices('0123456789',k=random.randint(8,15)))
def gen_fastag(): return ''.join(random.choices(string.ascii_uppercase+'0123456789',k=random.randint(10,20)))
def gen_upi():
    names=['rahul','priya','amit','raj','neha']; banks=['okicici','oksbi','okaxis','okhdfcbank','ybl','paytm','gpay']
    return f"{random.choice(names)}{random.randint(1,999)}@{random.choice(banks)}"
def gen_cvv():      return str(random.randint(100,999))
def gen_tan():      return ''.join(random.choices(string.ascii_uppercase,k=4))+''.join(random.choices('0123456789',k=5))+random.choice(string.ascii_uppercase)
def gen_cin():
    states_cin=['MH','DL','KA','TN','GJ','UP','WB','RJ','AP','KL']
    return f"{random.choice('LU')}{random.randint(10000,99999)}{random.choice(states_cin)}{random.randint(1990,2023)}{random.choice(['PLC','PVT','LLP'])}{random.randint(100000,999999)}"
def gen_micr():  return ''.join(random.choices('0123456789',k=9))
def gen_ip():    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def gen_mac():   return ':'.join(f'{random.randint(0,255):02X}' for _ in range(6))

# ── Table definitions ─────────────────────────────────────────────────────────

TABLES = {
    "users": {
        "email":        gen_email,
        "phone":        gen_phone,
        "pan_number":   gen_pan,
        "aadhaar":      gen_aadhaar,
        "voter_id":     gen_voter,
        "passport_no":  gen_passport,
    },
    "customers": {
        "gstin":            gen_gstin,
        "upi_id":           gen_upi,
        "driving_licence":  gen_dl,
        "vehicle_number":   gen_vehicle,
        "cin":              gen_cin,
        "tan":              gen_tan,
    },
    "payments": {
        "credit_card":   gen_card,
        "ifsc_code":     gen_ifsc,
        "bank_account":  gen_bank,
        "micr_code":     gen_micr,
        "cvv":           gen_cvv,
        "demat_account": gen_demat,
    },
    "kyc": {
        "loan_account":     gen_loan,
        "cheque_number":    gen_cheque,
        "cif_number":       gen_cif,
        "insurance_policy": gen_insurance,
        "fastag_id":        gen_fastag,
    },
    "network_logs": {
        "ip_address":  gen_ip,
        "mac_address": gen_mac,
    },
}

# ── Seed ──────────────────────────────────────────────────────────────────────

conn = psycopg2.connect(**DB)
cur  = conn.cursor()

for table, columns in TABLES.items():
    cols_def = ", ".join(f"{col} TEXT" for col in columns)
    cur.execute(f"DROP TABLE IF EXISTS {table};")
    cur.execute(f"CREATE TABLE {table} (id SERIAL PRIMARY KEY, {cols_def});")
    print(f"Created table: {table}")

    col_names = list(columns.keys())
    placeholders = ", ".join(["%s"] * len(col_names))
    insert_sql = f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({placeholders})"

    rows = []
    for _ in range(N):
        row = tuple(gen() for gen in columns.values())
        rows.append(row)

    cur.executemany(insert_sql, rows)
    print(f"  Inserted {N} rows into {table}")

conn.commit()
cur.close()
conn.close()
print("\nDone! All tables seeded successfully.")