import psycopg2, random, string, sys
from psycopg2.extras import execute_values

random.seed(42)

def verhoeff_digit(s):
    D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    for cd in range(10):
        c=0
        for i,ch in enumerate(reversed(s+str(cd))): c=D[c][P[i%8][int(ch)]]
        if c==0: return str(cd)

def luhn_digit(s):
    d=[int(c) for c in s]; t,p=0,(len(d)+1)%2
    for i,x in enumerate(d):
        if i%2==p: x*=2; x-=9 if x>9 else 0
        t+=x
    return str((10-t%10)%10)

def gstin_check(base):
    chars='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    s=0
    for i,c in enumerate(base):
        val=chars.index(c)
        if i%2==0: s+=val
        else:
            p=val*2; s+=p//36+p%36
    return chars[(36-s%36)%36]

IN_STATES=['AP','AR','AS','BR','CG','CH','DL','GA','GJ','HP','HR','JH','JK','KA','KL','LA','MH','ML','MN','MP','MZ','NL','OD','PB','PY','RJ','SK','TN','TR','TS','UK','UP','WB']
BANKS=['SBIN','HDFC','ICIC','AXIS','KKBK','PUNB','CNRB','UBIN']
GST_STATES=[f'{i:02d}' for i in range(1,38)]
PAN_TYPES='PCHABGJLFT'
FIRST_NAMES=['Rahul','Priya','Amit','Sneha','Vikram','Anjali','Rajesh','Kavita','Suresh','Deepa','Arjun','Pooja','Ravi','Neha','Sanjay']
LAST_NAMES=['Sharma','Patel','Kumar','Singh','Gupta','Reddy','Nair','Iyer','Mehta','Joshi','Verma','Rao','Desai','Pillai','Chopra']
US_FIRST=['John','Jane','Mike','Sarah','David','Emily','James','Emma','Robert','Olivia']
US_LAST=['Smith','Johnson','Williams','Jones','Brown','Davis','Miller','Wilson']

def gen_aadhaar():
    base=str(random.randint(2,9))+''.join(random.choice('0123456789') for _ in range(10))
    return base+verhoeff_digit(base)

def gen_pan():
    return (''.join(random.choice(string.ascii_uppercase) for _ in range(3))+random.choice(PAN_TYPES)
            +random.choice(string.ascii_uppercase)+''.join(random.choice('0123456789') for _ in range(4))
            +random.choice(string.ascii_uppercase))

def gen_mobile():
    return random.choice('6789')+''.join(random.choice('0123456789') for _ in range(9))

def gen_bank_account():
    return ''.join(random.choice('0123456789') for _ in range(random.choice([11,14,15,17,18])))

def gen_ifsc():
    return random.choice(BANKS)+'0'+''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(6))

def gen_gstin():
    state=random.choice(GST_STATES)
    pan=gen_pan()
    entity=random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    base=state+pan+entity+'Z'
    return base+gstin_check(base)

def gen_card():
    prefix=random.choice(['4','51','52','60','65','81'])
    body=prefix+''.join(random.choice('0123456789') for _ in range(15-len(prefix)))
    return body+luhn_digit(body)

def gen_ssn():
    area=random.choice(list(range(1,666))+list(range(667,900)))
    return f"{area:03d}-{random.randint(1,99):02d}-{random.randint(1,9999):04d}"

def gen_itin():
    area=random.randint(900,999)
    groups=list(range(50,66))+list(range(70,89))+list(range(90,93))+list(range(94,100))
    return f"{area}-{random.choice(groups):02d}-{random.randint(1,9999):04d}"

def gen_name_in(): return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
def gen_name_us(): return f"{random.choice(US_FIRST)} {random.choice(US_LAST)}"
def gen_email(name): return f"{name.lower().replace(' ','.')}@{'gmail.com' if random.random()<0.5 else 'company.com'}"

UPI_HANDLES = [
    'ybl','ibl','axl','okaxis','okhdfcbank','okicici','oksbi','paytm',
    'ptsbi','pthdfc','ptaxis','ptyes','apl','rapl','yapl','waaxis',
    'waicici','wahdfcbank','wasbi','yesg','yescred','yespop','superyes',
    'ikwik','mvhdfc','fkaxis','indie','federal','fifederal','icici',
    'axisb','hsbc','idbi','indianbank','allbank','kotak','kotak811',
    'barodampay','pnb','unionbank','canara','bob','sbi','hdfcbank',
    'icicibank','axisbank','idfcfirst','idfc','rbl','bandhan','yesbank',
    'indus','indusind','au','aubank','equitas','ujjivan','airtel',
    'freecharge','famapp','slice','cred','groww','jupiter','mobikwik',
    'amazonpay','flipkart','phonepe','gpay','bhim'
]

COMPANY_TYPES = [
    'PTC','PLC','OPC','SGC','FTC','GOI','NPL','ULT','FLC'
]


def gen_upi():
    first = ['rahul','priya','amit','sneha','vikram','anjali','ravi','neha','sanjay','pooja']
    last = ['sharma','patel','kumar','singh','gupta','reddy','nair','mehta','joshi','verma']

    fmt = random.randint(0, 4)

    if fmt == 0:
        username = random.choice(first) + '.' + random.choice(last)
    elif fmt == 1:
        username = random.choice('6789') + ''.join(random.choice('0123456789') for _ in range(9))
    elif fmt == 2:
        username = random.choice(first) + str(random.randint(1, 999))
    elif fmt == 3:
        username = random.choice(first) + '_' + random.choice(last)
    else:
        username = random.choice(first) + random.choice(last)

    return username + '@' + random.choice(UPI_HANDLES)


def gen_cvv():
    if random.random() < 0.2:
        return str(random.randint(1000, 9999))
    return str(random.randint(100, 999))


def gen_tan():
    jurisdiction = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    deductor = random.choice(string.ascii_uppercase)
    seq = ''.join(random.choice('0123456789') for _ in range(5))
    last = random.choice(string.ascii_uppercase)
    return jurisdiction + deductor + seq + last


def gen_cin():
    listing = random.choice(['L', 'U'])
    industry = f"{random.randint(10000, 99999)}"
    state = random.choice(IN_STATES)
    year = str(random.randint(1956, 2024))
    ctype = random.choice(COMPANY_TYPES)
    reg = f"{random.randint(100000, 999999)}"
    return listing + industry + state + year + ctype + reg


def gen_micr():
    city = f"{random.randint(100, 799):03d}"
    bank = f"{random.randint(1, 999):03d}"
    branch = f"{random.randint(1, 999):03d}"
    return city + bank + branch

def main(n_per_table=1000):
    conn = psycopg2.connect(dbname="pii_demo", user="postgres", host="localhost")
    cur = conn.cursor()

    print(f"Populating tables with {n_per_table} rows each (batch mode)...")
    BATCH = 5000

    # Table 1: customers_clean
    rows = []
    for _ in range(n_per_table):
        name = gen_name_in()
        rows.append((name, gen_email(name), gen_aadhaar(), gen_pan(), gen_mobile(), gen_bank_account(), gen_ifsc()))
        if len(rows) >= BATCH:
            execute_values(cur, """INSERT INTO customers_clean
                (full_name, email, aadhaar_number, pan_number, mobile_number, bank_account_number, ifsc_code)
                VALUES %s""", rows)
            conn.commit()
            rows = []
    if rows:
        execute_values(cur, """INSERT INTO customers_clean
            (full_name, email, aadhaar_number, pan_number, mobile_number, bank_account_number, ifsc_code)
            VALUES %s""", rows)
        conn.commit()
    print("customers_clean done")

    # Table 2: legacy_records
    rows = []
    for _ in range(n_per_table):
        rows.append((gen_name_in(), gen_email("test"), gen_aadhaar(), gen_gstin(), gen_pan(),
                      gen_ifsc(), gen_mobile(), gen_bank_account(), "Customer service note - no PII here normally"))
        if len(rows) >= BATCH:
            execute_values(cur, """INSERT INTO legacy_records
                (field_12, field_23, field_47, ref_code, serial_val, identifier, data_point, misc_value, notes)
                VALUES %s""", rows)
            conn.commit()
            rows = []
    if rows:
        execute_values(cur, """INSERT INTO legacy_records
            (field_12, field_23, field_47, ref_code, serial_val, identifier, data_point, misc_value, notes)
            VALUES %s""", rows)
        conn.commit()
    print("legacy_records done")

    # Table 3: global_employees
    rows = []
    for _ in range(n_per_table):
        is_india = random.random() < 0.5
        name = gen_name_in() if is_india else gen_name_us()
        rows.append((name, gen_email(name), "India" if is_india else "USA",
                      gen_aadhaar() if is_india else None,
                      gen_pan() if is_india else None,
                      None if is_india else gen_ssn(),
                      None if is_india else gen_itin(),
                      gen_mobile() if is_india else f"555-{random.randint(100,999)}-{random.randint(1000,9999)}",
                      random.randint(40000, 200000)))
        if len(rows) >= BATCH:
            execute_values(cur, """INSERT INTO global_employees
                (employee_name, work_email, country, india_aadhaar, india_pan, us_ssn, us_itin, phone, salary)
                VALUES %s""", rows)
            conn.commit()
            rows = []
    if rows:
        execute_values(cur, """INSERT INTO global_employees
            (employee_name, work_email, country, india_aadhaar, india_pan, us_ssn, us_itin, phone, salary)
            VALUES %s""", rows)
        conn.commit()
    print("global_employees done")

    # Table 4: bank_transactions
# Table 4: bank_transactions
    rows = []
    for i in range(n_per_table):
        rows.append((f"TXN{100000+i}", gen_bank_account(), gen_ifsc(), gen_bank_account(), gen_ifsc(),
                      gen_gstin(), round(random.uniform(100, 100000), 2)))
        if len(rows) >= BATCH:
            execute_values(cur, """INSERT INTO bank_transactions
                (transaction_id, sender_account, sender_ifsc, receiver_account, receiver_ifsc, company_gstin, amount, transaction_date)
                VALUES %s""", rows, template="(%s,%s,%s,%s,%s,%s,%s,NOW())")
            conn.commit()
            rows = []
    if rows:
        execute_values(cur, """INSERT INTO bank_transactions
            (transaction_id, sender_account, sender_ifsc, receiver_account, receiver_ifsc, company_gstin, amount, transaction_date)
            VALUES %s""", rows, template="(%s,%s,%s,%s,%s,%s,%s,NOW())")
        conn.commit()
    print("bank_transactions done")
    # Table 5: product_catalog
# Table 5: product_catalog
    products = ['Laptop','Mouse','Keyboard','Monitor','Webcam','Headphones','Desk','Chair','Lamp','Cable']
    rows = []
    for i in range(n_per_table):
        rows.append((random.choice(products), f"SKU-{1000+i}", "Electronics",
                      round(random.uniform(10, 2000), 2), random.randint(0, 500)))
        if len(rows) >= BATCH:
            execute_values(cur, """INSERT INTO product_catalog
                (product_name, sku, category, price, stock_quantity, last_updated)
                VALUES %s""", rows, template="(%s,%s,%s,%s,%s,NOW())")
            conn.commit()
            rows = []
    if rows:
        execute_values(cur, """INSERT INTO product_catalog
            (product_name, sku, category, price, stock_quantity, last_updated)
            VALUES %s""", rows, template="(%s,%s,%s,%s,%s,NOW())")
        conn.commit()
    print("product_catalog done")
    # Table 6: financial_pii_test
    rows = []
    for _ in range(n_per_table):
         rows.append((
        "IN" + ''.join(random.choice('0123456789') for _ in range(14)),              # demat
        ''.join(random.choice('0123456789') for _ in range(6)),                      # cheque
        ''.join(random.choice('0123456789') for _ in range(random.randint(8, 12))),  # cif
        "LN" + ''.join(random.choice('0123456789') for _ in range(10)),              # loan
        "LIC" + ''.join(random.choice('0123456789') for _ in range(12)),             # insurance
        "FT" + ''.join(random.choice('0123456789') for _ in range(12)),              # fastag
        gen_upi(),
        str(random.randint(100, 999)),
        gen_tan(),
        gen_cin(),
        gen_micr(),
    ))

    if len(rows) >= BATCH:
        execute_values(cur, """
            INSERT INTO financial_pii_test
            (
                demat_account,
                cheque_number,
                cif_number,
                loan_account_number,
                insurance_policy_number,
                fastag_id,
                upi_id,
                cvv,
                tan,
                cin,
                micr_code
            )
            VALUES %s
        """, rows)
        conn.commit()
        rows = []

    if rows:
      execute_values(cur, """
        INSERT INTO financial_pii_test
        (
            demat_account,
            cheque_number,
            cif_number,
            loan_account_number,
            insurance_policy_number,
            fastag_id,
            upi_id,
            cvv,
            tan,
            cin,
            micr_code
        )
        VALUES %s
    """, rows)
    conn.commit()

    print("financial_pii_test done")

    cur.close()
    conn.close()
    print("Done.")

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    main(n)
