import csv, random, string, os
from datetime import datetime

random.seed(2024)
N = 5000  # samples per entity

# ── Validators ──────────────────────────────────────────────────────────────
def luhn_digit(s):
    d=[int(c) for c in s]; t,p=0,(len(d)+1)%2
    for i,x in enumerate(d):
        if i%2==p: x*=2; x-=9 if x>9 else 0
        t+=x
    return str((10-t%10)%10)

VERHOEFF_D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
VERHOEFF_P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
def verhoeff_valid(num):
    c=0
    for j,d in enumerate(reversed(num)):
        c=VERHOEFF_D[c][VERHOEFF_P[j%8][int(d)]]
    return c==0

def verhoeff_check_digit(num):
    inv=[0,4,3,2,1,9,8,7,6,5]
    c=0
    for i,d in enumerate(reversed(num)):
        c=VERHOEFF_D[c][VERHOEFF_P[(i+1)%8][int(d)]]
    return str(inv[c])

def gstin_check(s14):
    chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cm={c:i for i,c in enumerate(chars)}
    total=0
    for i,c in enumerate(s14.upper()):
        v=cm[c]; total+= v if i%2==0 else (v*2)//36+(v*2)%36
    return chars[(36-total%36)%36]

# ── India Entity Generators ──────────────────────────────────────────────────
STATES=['AP','AR','AS','BR','CG','CH','DL','GA','GJ','HP','HR','JH','JK','KA','KL','LA','MH','ML','MN','MP','MZ','NL','OD','PB','PY','RJ','SK','TN','TR','TS','UK','UP','WB','AN','DD','DN']

def gen_aadhaar():
    base=str(random.randint(2,9))+''.join(random.choices('0123456789',k=10))
    for check in range(10):
        candidate=base+str(check)
        if verhoeff_valid(candidate):
            return candidate
    return gen_aadhaar()  # retry on rare failure

def gen_pan():
    letters=string.ascii_uppercase
    types='PCFHBGJLPT'
    return ''.join(random.choices(letters,k=3))+random.choice(types)+random.choice(letters)+''.join(random.choices('0123456789',k=4))+random.choice(letters)

def gen_passport():
    series='ABCDEFGHJKNPRSTUVWYZ'
    return random.choice(series)+str(random.randint(1000000,9999999))

def gen_voter():
    return ''.join(random.choices(string.ascii_uppercase,k=3))+''.join(random.choices('0123456789',k=7))

def gen_dl_in():
    state=random.choice(STATES)
    rto=f"{random.randint(1,99):02d}"
    year=random.randint(1990,2023)
    serial=f"{random.randint(1000000,9999999)}"
    return f"{state}{rto}{year}{serial}"

def gen_vehicle_in():
    state=random.choice(STATES)
    dist=f"{random.randint(1,99):02d}"
    letters=''.join(random.choices(string.ascii_uppercase,k=random.choice([1,2])))
    num=f"{random.randint(1,9999):04d}"
    return f"{state}{dist}{letters}{num}"

def gen_mobile_in():
    return str(random.randint(6,9))+''.join(random.choices('0123456789',k=9))

def gen_email():
    names=['rahul','priya','amit','sara','raj','neha','vijay','kavya','suresh','pooja']
    domains=['gmail.com','yahoo.com','hotmail.com','outlook.com','rediffmail.com']
    return f"{random.choice(names)}{random.randint(1,999)}@{random.choice(domains)}"

def gen_gstin():
    state=f"{random.randint(1,37):02d}"
    pan=gen_pan()
    entity=random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    partial=state+pan+entity+'Z'
    check=gstin_check(partial)
    return partial+check

def gen_abha():
    # Format: XX-XXXX-XXXX-XXXX
    return (
        f"{random.randint(10,99)}-"
        f"{random.randint(1000,9999)}-"
        f"{random.randint(1000,9999)}-"
        f"{random.randint(1000,9999)}"
    )

def gen_esic():
    return (f"{random.randint(10,99)}-"
            f"{random.randint(10,99)}-"
            f"{random.randint(100000,999999)}-"
            f"{random.randint(100,999)}-"
            f"{random.randint(1000,9999)}")

def gen_dob():
    day = random.randint(1, 28)
    month = random.randint(1, 12)
    year = random.randint(1950, 2005)
    fmt = random.choice([
        f"{day:02d}/{month:02d}/{year}",
        f"{day:02d}-{month:02d}-{year}",
        f"{year}-{month:02d}-{day:02d}",
        f"{day:02d}.{month:02d}.{year}",
    ])
    return fmt

def gen_location():
    # India lat/long bounds
    lat = round(random.uniform(8.0, 37.0), 4)
    lng = round(random.uniform(68.0, 97.0), 4)
    return f"{lat}, {lng}"

def gen_ration_card():
    states = ['MH','DL','KA','TN','GJ','UP','WB','RJ','AP','KL','MP','HR']
    return random.choice(states) + '-' + ''.join(random.choices('0123456789', k=random.randint(10,13)))

def gen_sebi():
    prefixes = ['INZ','INH','INP','INR','INA','INM','INQ']
    return random.choice(prefixes) + ''.join(random.choices('0123456789', k=9))

def gen_uan():
    return str(random.randint(100000000000, 999999999999))

def gen_epf_member_id():
    state = random.choice([
        "AP","AR","AS","BR","CG","DL","GA","GJ","HR","HP","JK","JH",
        "KA","KL","MP","MH","MN","ML","MZ","NL","OD","PB","RJ",
        "SK","TN","TS","TR","UP","UK","WB","CH","PY"
    ])

    office = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    establishment = f"{random.randint(0, 9999999):07d}"
    member = f"{random.randint(1, 9999999999):010d}"

    return f"{state}{office}{establishment}{member}"

def gen_ifsc():
    banks=['SBIN','HDFC','ICIC','AXIS','PUNB','UBIN','BKID','CNRB','IOBA','VIJB']
    return random.choice(banks)+'0'+''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',k=6))

def gen_bank_in():
    length=random.choice([9,11,14,15,17,18])
    return ''.join(random.choices('0123456789',k=length))

def gen_card():
    networks=[('4',16),('52',16),('34',15),('6011',16),('2221',16)]
    prefix,length=random.choice(networks)
    body=prefix+''.join(random.choices('0123456789',k=length-1-len(prefix)))
    return body+luhn_digit(body)

def gen_demat():
    return 'IN'+''.join(random.choices('0123456789',k=14))

def gen_cheque():
    return ''.join(random.choices('0123456789',k=6))

def gen_cif():
    return ''.join(random.choices('0123456789',k=random.randint(8,11)))

def gen_loan():
    return ''.join(random.choices(string.ascii_uppercase,k=2))+''.join(random.choices('0123456789',k=random.randint(8,18)))

def gen_insurance():
    prefixes=['LIC','SBI','MAX','HDG','ICL']
    return random.choice(prefixes)+''.join(random.choices('0123456789',k=random.randint(8,15)))

def gen_fastag():
    return ''.join(random.choices(string.ascii_uppercase+'0123456789',k=random.randint(10,20)))

def gen_upi():
    names=['rahul','priya','amit','raj','neha']
    banks=['okicici','oksbi','okaxis','okhdfcbank','ybl','paytm','gpay']
    return f"{random.choice(names)}{random.randint(1,999)}@{random.choice(banks)}"

def gen_cvv():
    return str(random.randint(100,999))

def gen_tan():
    return ''.join(random.choices(string.ascii_uppercase,k=4))+''.join(random.choices('0123456789',k=5))+random.choice(string.ascii_uppercase)

def gen_cin():
    types=['L','U']
    states_cin=['MH','DL','KA','TN','GJ','UP','WB','RJ','AP','KL']
    entity=random.choice(['PLC','PVT','LLP'])
    return f"{random.choice(types)}{random.randint(10000,99999)}{random.choice(states_cin)}{random.randint(1990,2023)}{entity}{random.randint(100000,999999)}"

def gen_micr():
    return ''.join(random.choices('0123456789',k=9))

def gen_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def gen_mac():
    return ':'.join(f'{random.randint(0,255):02X}' for _ in range(6))

# ── Negative generators ──────────────────────────────────────────────────────
def gen_neg():
    choices=[
        lambda: str(random.randint(10000000,99999999)),
        lambda: ''.join(random.choices(string.ascii_uppercase+string.digits,k=random.randint(6,12))),
        lambda: f"{random.randint(100,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}",
        lambda: f"ORD{random.randint(100000,999999)}",
        lambda: f"INV{random.randint(10000,99999)}",
        lambda: str(random.randint(2020,2025))+'-'+str(random.randint(1,12)).zfill(2)+'-'+str(random.randint(1,28)).zfill(2),
    ]
    return random.choice(choices)()

# ── Build benchmark ──────────────────────────────────────────────────────────
GENS = {
    'AdharcardNumber':     gen_aadhaar,
    'PANNumber':           gen_pan,
    'PassportNumber':      gen_passport,
    'VoterID':             gen_voter,
    'DrivingLicenceNumber':gen_dl_in,
    'VehicleNumber':       gen_vehicle_in,
    'Phone':               gen_mobile_in,
    'Email':               gen_email,
    'GSTIN':               gen_gstin,
    'IFSC':                gen_ifsc,
    'BankAccountNumber':   gen_bank_in,
    'CreditCard':          gen_card,
    'DematAccountNumber':  gen_demat,
    'ChequeNumber':        gen_cheque,
    'CIFNumber':           gen_cif,
    'LoanAccountNumber':   gen_loan,
    'InsurancePolicyNumber':gen_insurance,
    'FASTagID':            gen_fastag,
    'UPIID':               gen_upi,
    'CVV':                 gen_cvv,
    'TAN':                 gen_tan,
    'CIN':                 gen_cin,
    'IPAddress':           gen_ip,
    'MacAddress':          gen_mac,
    "ABHANumber":          gen_abha,
    "UAN":                 gen_uan,
    "EPFMemberID":         gen_epf_member_id,
    "ESIC":                gen_esic,
    "RationCard":          gen_ration_card,
    "SEBIRegistration":    gen_sebi,
    "BirthDate":           gen_dob,
    "Location":            gen_location,
}

rows=[]
for label,gen in GENS.items():
    for _ in range(N): rows.append((gen(),label))

neg_count=len(GENS)*N*3
for _ in range(neg_count): rows.append((gen_neg(),'NEG'))

random.shuffle(rows)
os.makedirs('benchmark',exist_ok=True)
path=os.path.join('benchmark','india_benchmark.csv')
with open(path,'w',newline='') as f:
    w=csv.writer(f); w.writerow(['value','label']); w.writerows(rows)

pos=len(GENS)*N
print(f"Generated {len(rows):,} samples ({pos:,} positive across {len(GENS)} entities, {neg_count:,} negative)")
print(f"Saved to {path}")
