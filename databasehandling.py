import sqlite3
import os
from packaging import version

#define the path to the database file
db_file = r'C:\Users\Yassine\Downloads\nvdcve_2.db'

# Check if file exists and get size
if os.path.exists(db_file):
    file_size = os.path.getsize(db_file)
    print(f"Database file exists. Size: {file_size} bytes")
else:
    print(f"ERROR: Database file '{db_file}' not found!")
    exit(1)

# connect to the data base 
db = sqlite3.connect(db_file)

# create a cursor object to interact with the database
cur = db.cursor()

# List all available tables:
# * all available tables in the database
# ID all the colum ID available PRODUCTS table
# VENDOR all the colum VENDOR available PRODUCTS table
# The Query to select the first 20 rows of the ID column from the PRODUCTS table
cur.execute("SELECT * FROM PRODUCTS LIMIT 20")

# fetch the first row of the table
print("First row of the table:")
print(cur.fetchone())

# fetch the 5 rows of the table
print("First 5 rows of the table:")
print(cur.fetchmany(5))

# fetch all rows and perform some operations
print("All rows of the table:")
cve_id = cur.fetchall()
print(f"Total rows in database: {len(cve_id)}")
for cve in cve_id:
    print(cve)

# add a condition to filter the results based on the CVE ID
print("Filtered rows (CVE-1999-1122):")
for cve in cve_id:
    print(cve)
    if cve[0] == 'CVE-1999-1122':  # Access the first column of the tuple
        print(cve)
    else:
        continue

# Query to filter the results based on the CVE ID or other colums
print("Query to filter the results based on the CVE ID or other colums:")
cur.execute("SELECT * FROM PRODUCTS WHERE VENDOR = 'ftp'")
#cve_id = cur.fetchall()
print(f"Total rows in database: {len(cve_id)}")

for cve in cve_id:
    print(cve)

# Query to filter the results based on the first 4 characters of the CVE ID
print("Query to filter the results based on the first 4 characters of the CVE ID:")
cur.execute("SELECT * FROM PRODUCTS WHERE ID like 'CVE-1999-148%'")
#cve_id = cur.fetchall()
print(f"Total rows in database: {len(cve_id)}")

for cve in cve_id:
    print(cve)

# Query to for Advanced filtring and search inside the database using the LIKE operator and wildcards
print("Query to for Advanced filtring and search inside the database using the LIKE operator and wildcards")
product = "openssl"
vendor = "%openssl%" 

for cverow in cur.execute("""
    SELECT DISTINCT ID FROM PRODUCTS
    WHERE PRODUCT = ? AND VENDOR LIKE ?
""", (product, vendor)):

    cve = cverow[0]   

    for row in cur.execute("""
        SELECT version_start, operator_start, version_end, operator_end
        FROM PRODUCTS
        WHERE ID = ? AND PRODUCT = ? AND VENDOR LIKE ?
        LIMIT 5
    """, (cve, product, vendor)):

        version_start, operator_start, version_end, operator_end = row

        print(cve, version_start, operator_start, version_end, operator_end)
# Query to check all the different operators used in the database
print("Query to check all the different operators start used in the database:")
cur.execute("SELECT DISTINCT OPERATOR_START FROM PRODUCTS")
cve_id = cur.fetchall()
for cve in cve_id:
    print(cve)

print("Query to check all the different operators end used in the database:")
cur.execute("SELECT DISTINCT OPERATOR_END FROM PRODUCTS")
cve_id = cur.fetchall()
for cve in cve_id:
    print(cve)

print("Query to check all the different versions used in the database:")
cur.execute("SELECT DISTINCT VERSION_END, VERSION_START FROM PRODUCTS")
ver = cur.fetchall()
results = []
for version_end, version_start in ver:
    results.append(str(version_end) + " | " + str(version_start) + "\n")

with open("versions.txt", "w", encoding="utf-8") as f:
    f.writelines(results)

print("------------------------------------------------------------------------------------")
print("-                               Testing the function                               -")
print("------------------------------------------------------------------------------------")

def parse(v):
    if not v or v == "-":
        return None
    try:
        return version.parse(v)
    except:
        return None


def check_vulnerable(installed_v, start_v, start_op, end_v, end_op):

    v = parse(installed_v)

    # -------------------------
    # CASE 1: only END bound
    # -------------------------
    if end_v:
        ve = parse(end_v)

        if end_op == "<=":
            if not (v <= ve):
                return False
        elif end_op == "<":
            if not (v < ve):
                return False

    # -------------------------
    # CASE 2: only START bound
    # -------------------------
    if start_v:
        vs = parse(start_v)

        if start_op == ">=":
            if not (v >= vs):
                return False
        elif start_op == ">":
            if not (v > vs):
                return False
        elif start_op == "=":
            if not (v == vs):
                return False

    return True

def get_vulnerabilities(conn, product, vendor, installed_version):

    vendor_pattern = f"%{vendor}%"

    query = """
        SELECT ID, version_start, operator_start, version_end, operator_end
        FROM PRODUCTS
        WHERE PRODUCT = ?
        AND VENDOR LIKE ?
    """

    results = []

    for cve_id, v_start, op_start, v_end, op_end in conn.execute(query, (product, vendor_pattern)):

        if check_vulnerable(installed_version, v_start, op_start, v_end, op_end):
            results.append(cve_id)

    return list(set(results))


product = "dec_openvms"
vendor = "dec"
installed_version = "5.5.8"   # your actual package version

cves = get_vulnerabilities(cur, product, vendor, installed_version)

for cve in cves:
    print(cve)

db.commit()
db.close()

