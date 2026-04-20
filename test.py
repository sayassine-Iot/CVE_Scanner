import sqlite3
import os
import re
from packaging import version

#define the path to the database file
db_file = r'C:\Users\Yassine\Downloads\meta-cve-wrapper\nvdcve_2.db'

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

# Cache DB query results and per-version CVE computations
_rows_cache = {}
_cve_cache = {}

def normalize_version(raw_version):
    # Keep only the leading numeric version (e.g. 1.18.5.imx -> 1.18.5, 2.0.0+git0+... -> 2.0.0)
    match = re.match(r'^(\d+(?:\.\d+)*)', raw_version.strip())
    return match.group(1) if match else raw_version.strip()

# Parse and check the manifest file
manifest_file = r'C:\Users\Yassine\Downloads\meta-cve-wrapper\20260417103322.rootfs.manifest'
def parse_manifestfile(file_path):
    #open the manifest file and read its contents
    with open(file_path, "r") as f:
        lines = f.readlines()

    # Initialize variables to store product, vendor, and version information
    packages = []
    for line in lines:
        line = line.strip()
        if line:  # Skip empty lines
            parts = line.split()
            if len(parts) >= 3:
                package_name = parts[0]
                architecture = parts[1]
                version = parts[2]
                packages.append({
                    'name': package_name,
                    'architecture': architecture,
                    'version': version
                })

    return packages

def check_vulnerable(installed_v, start_v, start_op, end_v, end_op):
    v = version.parse(normalize_version(installed_v))

    # CASE 1: only END bound
    if end_v:
        ve = version.parse(normalize_version(end_v))

        if end_op == "<=":
            if not (v <= ve):
                return False
        elif end_op == "<":
            if not (v < ve):
                return False

    # CASE 2: only START bound
    if start_v:
        vs = version.parse(normalize_version(start_v))

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
    cache_key = (vendor, product, normalize_version(installed_version))
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    vendor_pattern = f"%{vendor}%"

    rows_key = (vendor, product)
    if rows_key not in _rows_cache:
        query = """
            SELECT ID, version_start, operator_start, version_end, operator_end
            FROM PRODUCTS
            WHERE PRODUCT = ?
            AND VENDOR LIKE ?
        """
        _rows_cache[rows_key] = list(conn.execute(query, (product, vendor_pattern)))

    results = []

    for cve_id, v_start, op_start, v_end, op_end in _rows_cache[rows_key]:
        if check_vulnerable(installed_version, v_start, op_start, v_end, op_end):
            results.append(cve_id)

    deduped = sorted(set(results))
    _cve_cache[cache_key] = deduped
    return deduped

if os.path.exists(manifest_file):
    print(f"\nManifest file found: {manifest_file}")
    packages = parse_manifestfile(manifest_file)
    all_cves = set()

    for i, pkg in enumerate(packages):
        # get vendor/product
        if pkg['name'].startswith("gstreamer1.0"):
            vendor, product = ("gstreamer", "gstreamer")
            cves = get_vulnerabilities(cur, product, vendor, pkg["version"])
            all_cves.update(cves)
            #clean_version = normalize_version(pkg["version"])
            #print(f"Package {i+1}: {pkg['name']} | Vendor: {vendor} | Product: {product} | Version: {clean_version} | CVEs: {len(cves)}")

else:
    print(f"ERROR: Manifest file '{manifest_file}' not found!")
    all_cves = set()

for cve in sorted(all_cves):
    print(cve)

db.close()
