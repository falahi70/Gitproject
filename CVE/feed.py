#!/usr/bin/env python3
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import urllib.request
import zipfile
import os
import psycopg2
import datetime
import re
import json
import time
import requests
from modules.database_connections import *
from modules.general_functions import *

try:
    config = load_config()
except Exception as e:
    print(f"[-] Faield to load config file.\n[Err] {e}")
    sys.exit(0)

database_handle = databaseConnection(
    config["database_connection"]["ipaddress"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)


def download_url(url, save_path, chunk_size=128):
    request_handle = requests.get(url, stream=True, timeout=3)
    with open(save_path, 'wb') as fd:
        for chunk in request_handle.iter_content(chunk_size=chunk_size):
            fd.write(chunk)


url = r"https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=140"
new_format = "%Y-%m-%d %H:%M:00"


def time_fix(btime):
    try:
        f_date = re.search("\d+\-\d+\-\d+",btime)
        f_date = f_date.group(0)
        f_time = re.search("\d+\:\d+\:\d+",btime)
        f_time = f_time.group(0)
        final = f"{f_date} {f_time}"
        return final
    except:
        b_time = datetime.datetime.now()
        b_time = str(b_time)
        f_date = re.search("\d+\-\d+\-\d+", b_time)
        f_date = f_date.group(0)
        f_time = re.search("\d+\:\d+\:\d+", b_time)
        f_time = f_time.group(0)
        final = f"{f_date} {f_time}"
        return final

def update_row(cve_id,updated):
    conn, cursor = connect_db()
    updated = time_fix(updated)
    get_old_date_sql = f'SELECT "modifiedDate" FROM cve_feeds.cve_data where "CVE_ID"=\'{cve_id}\';'
    old_time = cursor.execute(get_old_date_sql)
    try:
        old_time = old_time.fetchall()[0][0]
    except Exception as e:
        old_time = '1999-01-01 00:00:00'
    old_time = str(old_time)
    if updated>old_time:
        delete_old_data_sql = f"DELETE FROM cve_feeds.cve_data WHERE \"CVE_ID\"='{cve_id}';"
        cursor.execute(delete_old_data_sql)
        conn.commit()

added_count = 0
updated_count = 0


print("[+] Trying To Connect To [nvd.nist.gov].")
while True:
    try:
        url = config["cve_url"]
        download_url(url, 'recent.zip', chunk_size=128)
        print("[+] Latest CVE zip file downloaded.")
        with zipfile.ZipFile('recent.zip', 'r') as zip_ref:
            zip_ref.extractall()
        print("[+] Zip File Extracted.")
        extracted_filename = "nvdcve-1.1-recent.json"
        f = open(extracted_filename, "r", encoding="utf8")
        file = json.loads(f.read())
        f.close()
        break
    except Exception as e:
        print(f"[-] Failed To Connect To [nvd.nist.gov]. [Err] {e}")
        time.sleep(2)

insert_db_datas = []
print("[+] Going Through CVE Datas.")
for item in file["CVE_Items"]:
    cve_model = {}

    cve_id = item["cve"]["CVE_data_meta"]["ID"]
    cve_model["cve_id"] = cve_id

    try:
        refnumber = item["cve"]["references"]["reference_data"][0]["url"]
    except:
        refnumber = "-"
    refnumber = refnumber.replace("'", "")
    cve_model["reference"] = refnumber

    try:
        summary = item["cve"]["description"]["description_data"][0]["value"]
    except:
        summary = "-"
    summary = summary.replace("'", "")
    cve_model["description"] = summary

    published = item["publishedDate"]
    published = published.replace("'", "")
    d1 = datetime.datetime.strptime(published, "%Y-%m-%dT%H:%MZ")
    published = d1.strftime(new_format)

    LastModified = item["lastModifiedDate"]
    LastModified = LastModified.replace("'", "")
    d1 = datetime.datetime.strptime(LastModified, "%Y-%m-%dT%H:%MZ")
    LastModified = d1.strftime(new_format)

    cve_model["publisheddate"] = published
    cve_model["modifieddate"] = LastModified

    try:
        cvss = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
    except:
        cvss = "0"
    cve_model["cvss"] = cvss


    try:
        Severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
    except:
        Severity = "-"
    cve_model["severity"] = Severity

    try:
        exploitabilityScore = item["impact"]["baseMetricV3"]["exploitabilityScore"]
    except:
        exploitabilityScore = "-"
    cve_model["exploitabilityscore"] = exploitabilityScore

    try:
        impactScore = item["impact"]["baseMetricV3"]["impactScore"]
    except:
        impactScore = "-"
    cve_model["impactscore"] = impactScore

    try:
        attackVector = item["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
    except:
        attackVector = "-"
    cve_model["attackvector"] = attackVector

    try:
        attackComplexity = item["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]
    except:
        attackComplexity = "-"
    cve_model["attackcomplexity"] = attackComplexity

    try:
        privilegesRequired = item["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"]
    except:
        privilegesRequired = "-"
    cve_model["privilegesrequired"] = privilegesRequired

    try:
        userInteraction = item["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]
    except:
        userInteraction = "-"
    cve_model["userinteraction"] = userInteraction

    try:
        confidentialityImpact = item["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
    except:
        confidentialityImpact = "-"
    cve_model["confidentialityimpact"] = confidentialityImpact

    try:
        integrityImpact = item["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
    except:
        integrityImpact = "-"
    cve_model["integrityimpact"] = integrityImpact

    try:
        availabilityImpact = item["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
    except:
        availabilityImpact = "-"
    cve_model["availabilityimpact"] = availabilityImpact

    cpe_match = ""
    try:
        for match in item['configurations']['nodes'][0]['cpe_match']:
            x = match['cpe23Uri']
            # x = match['cpe23Uri'].replace("cpe:2.3:a:", "")
            # x = x.replace("cpe:2.3:o:", "")
            # x = x.replace(":*:*:*:*:*", "")
            # x = x.replace("'", "")
            cpe_match += f"{x},"
        cpe_match = cpe_match[:-1]
    except:
        cpe_match = "-"
    cve_model["cpe_match"] = cpe_match

    insert_db_datas.append(cve_model.copy())

db_data_length = len(insert_db_datas)
print(f"[+] Data length: [{db_data_length}]")

target_db_columns = database_handle.get_column_names("vulnerabilities", "cve_data")
header_row = ",".join(target_db_columns)

tmp_directory = os.getenv("tmp")
output_filename = f"{tmp_directory}\{generate_new_GUID()}_bulk.csv"
output_file_handle = open(output_filename, "w", encoding="utf-8", errors="ignore")
output_file_handle.write(f"{header_row}\n")

for data in insert_db_datas:
    tmp_row = ""
    for column in target_db_columns:
        insert_data = str(data.get(column, "N/A"))
        insert_data = insert_data.replace("\n", "")
        insert_data = insert_data.replace("\00", "")
        insert_data = insert_data.replace("`", "")
        insert_data = insert_data.replace(",", "")
        insert_data = insert_data.replace('"', "")
        tmp_row += f"{insert_data},"
    tmp_row = tmp_row[:-1]
    output_file_handle.write(f"{tmp_row}\n")
output_file_handle.close()
print(f"[+] Output Filename: {output_filename}")

try:
    os.chmod(output_filename, 0o777)
except Exception as e:
    print(f"[-] Failed to give permission to output file.\n[Err] {e}")



create_table_query = f'''drop table if exists vulnerabilities.tmp_table CASCADE;

            CREATE TABLE vulnerabilities.tmp_table 
            AS
            SELECT * 
            FROM vulnerabilities.cve_data
            WITH NO DATA;'''
database_handle.execute_sql(create_table_query)

insert_data_query = f'''
            copy vulnerabilities.tmp_table from '{output_filename}' CSV HEADER QUOTE '"';

            INSERT INTO vulnerabilities.cve_data
            SELECT DISTINCT ON (cve_id) *
            FROM vulnerabilities.tmp_table ON Conflict (cve_id) DO UPDATE SET cvss = EXCLUDED.cvss, severity = EXCLUDED.severity, exploitabilityscore = EXCLUDED.exploitabilityscore, impactscore = EXCLUDED.impactscore, reference = EXCLUDED.reference, description = EXCLUDED.description, cpe_match = EXCLUDED.cpe_match, attackvector = EXCLUDED.attackvector, attackcomplexity = EXCLUDED.attackcomplexity, privilegesrequired = EXCLUDED.privilegesrequired, userinteraction = EXCLUDED.userinteraction, confidentialityimpact = EXCLUDED.confidentialityimpact, integrityimpact = EXCLUDED.integrityimpact, availabilityimpact = EXCLUDED.availabilityimpact, modifieddate = EXCLUDED.modifieddate;
            '''
database_handle.execute_sql(insert_data_query)

try:
    os.remove('recent.zip')
    os.remove('nvdcve-1.1-recent.json')
except Exception as e:
    print("[-] Failed To Cleanup Files.")
