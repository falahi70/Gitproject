import argparse
import json
import subprocess
import sys
from modules.database_connections import *
from modules.general_functions import *
from modules.coresolution import *



parser = argparse.ArgumentParser(description="CoreInspect API Inventory Job Handler")

parser.add_argument("-ho", "--hostname",
                    default=False,
                    help='Comma,Separated list of target hostnames to add job queue.')

options = parser.parse_args()

config = load_config()
database_handle = databaseConnection(
    config["database_connection"]["host"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)

coresolution_handle = coresolution(
    config["coresolution"]["scheme"],
    config["coresolution"]["host"],
    config["coresolution"]["username"],
    config["coresolution"]["password"]
)
coresolution_handle.authenticate()

def get_hostnames():
    hostnames = []

    cpl = "|snippet    \"Get Windows_Linux Devices\""
    result = coresolution_handle.execute_cpl(cpl)
    for item in result:
        hostnames.append(item["hostName"])

    return hostnames

def create_new_job(hostname):
    sql_command = f"INSERT INTO \"server_management\".\"queue\" (\"hostname\", \"job\", \"queue_status\", \"db_status\", \"inventory_status\", \"filename\", \"created_time\", \"finished_time\") VALUES ('{hostname}', 'inventory', '0', '0', '0', 'N/A', '{current_time()}', '0000-00-00 00:00:00');"
    database_handle.execute_sql(sql_command)



if options.hostname:
    for hostname in options.hostname.split(","):
        try:
            create_new_job(hostname)
        except Exception as e:
            print(f"[-] Failed for hostname [{hostname}].\n[Err] {e}")
    print("Success")
else:
    hostname_list = get_hostnames()
    print(f"[*] Fetched [{len(hostname_list)}] hostnames from coresolution.")
    for hostname in hostname_list:
        try:
            create_new_job(hostname)
        except Exception as e:
            print(f"[-] Failed for hostname [{hostname}].\n[Err] {e}")
    print("Success")

