import sys
from modules.general_functions import *
from modules.database_connections import *
import os
import zipfile
import base64
import shutil
import time
from pydantic import BaseModel


config = load_config()

database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)

def process_file(filename, hostname):
    tmp_directory_name = f"{hostname}_{current_time(True)}_unzipped"

    try:
        fetch_ipaddress_sql = f"select request_host from server_management.access_logs where request_hostname='{hostname}' order by created_time desc LIMIT 1"
        # print(fetch_ipaddress_sql)
        hostname_ipaddress = database_handle.fetch_sql(fetch_ipaddress_sql)[0][0]
        hostname_ipaddress = ip2long(str(hostname_ipaddress))
    except Exception as e:
        hostname_ipaddress = "0"

    os.mkdir(tmp_directory_name)

    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_ref.extractall(tmp_directory_name)

    # try:
    #     os.remove(filename)
    # except Exception as e:
    #     print(f"[-] Failed to delete file [{filename}].")

    inventory_handle = open(f"{tmp_directory_name}/inventory_data.txt", "r", encoding="UTF-16", errors="ignore")
    # inventory_handle = open(filename, "r", encoding="UTF-16", errors="ignore")
    inventory_data_raw = inventory_handle.read()
    inventory_handle.close()
    inventory_data_raw = inventory_data_raw.strip()
    inventory_data_raw = inventory_data_raw.replace("\n", "")

    try:
        inventory_data = json.loads(inventory_data_raw, strict=False)
    except Exception as e:
        print(f"[-] Failed To Convert To JSON.\n[Err] {e}")
        inventory_data = {}

    bulk_insert_categories = ["userAccount",
                              "group",
                              "groupUser",
                              "service",
                              "product"]
    bulk_insert_categories = list(inventory_data.keys())


    for category in bulk_insert_categories:
        max_scanid = database_handle.get_max_scanid("asset_inventory", category, hostname)
        if str(max_scanid).lower() == "none":
            max_scanid = 1
        else:
            max_scanid += 1
        category_data = inventory_data.get(category, [])
        del inventory_data[category]

        if "list" not in str(type(category_data)):
            category_data = [category_data]

        insert_data = []
        for data in category_data:
            if category == "product":
                if str(data["name"]).lower() == "none":
                    continue
            data["id"] = generate_new_GUID()
            data["createdtime"] = current_time()
            data["hostname"] = hostname
            data["scanid"] = max_scanid
            data["query"] = "N/A"
            data["scannedip"] = hostname_ipaddress
            data["osfamily"] = "windows"
            insert_data.append(data.copy())

        database_handle.json2bulkdb("asset_inventory", category, insert_data)

    try:
        shutil.rmtree(tmp_directory_name)
    except Exception as e:
        print(f"[-] Failed to delete directory [{tmp_directory_name}].")

    try:
        os.remove(filename)
    except Exception as e:
        os.remove(filename)
        pass

    # insert_inventory_data(hostname, inventory_data)

while True:
    job = database_handle.pick_db_job()
    if not job:
        print("[-] No job found.")
        time.sleep(1)
        continue
    target_hostname = job["hostname"]
    inventory_data_filename = job["filename"]

    job["db_status"] = "2"
    database_handle.json_update("server_management", "queue", job.copy())

    try:
        process_file(inventory_data_filename, target_hostname)
        print("[+] inventory data inserted into DB.")
        job["db_status"] = "1"
        database_handle.json_update("server_management", "queue", job.copy())
    except Exception as e:
        print(f"[-] Failed To insert inventory data into DB.\n[Err] {e}")
        job["db_status"] = "-1"
        database_handle.json_update("server_management", "queue", job.copy())



