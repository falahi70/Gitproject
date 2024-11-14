import sys
from modules.coresolution_api_calls import *
from modules.database_connections import *
from modules.general_functions import *
import json
import concurrent.futures
from modules.coresolution import *
import os
from multiprocessing.pool import ThreadPool
import subprocess
import getpass


def load_config():
    config_file = json.load(open("appsettings.json", "r", encoding="utf-8", errors="ignore"))
    return config_file

config_data = load_config()

coresolution_handle = coresolution(
    config_data["coresolution_schema"],
    config_data["coresolution_ipaddress"],
    config_data["coresolution_username"],
    config_data["coresolution_password"])
coresolution_handle.authenticate()

def get_network_nodes(coresolution_handle):
    print("[+] Fetching data from coresolution.")
    cpl = r'''|   search      resourcetype        =   "snmpDiscovery"
                and status              =   "Enabled"
    |   fields  key         as  snmpDiscoveryKey,
                name        as  snmpDiscoveryName,
                ipAddress   as  snmpIpAddress,
                @connection as  connectionName
    |eval               snmpIpAddress:=longtoip(snmpIpAddress)
    | fields snmpIpAddress, connectionName,  snmpDiscoveryKey, snmpDiscoveryName
    '''.replace("\n", "")
    job_result = coresolution_handle.execute_cpl(cpl)
    ## Sample Data: {'_backgroundKey': 'SNMPDIS-1730', 'snmpIpAddress': '10.8.70.1', 'credName': 'SNMP-v3-InterVLAN-routing', 'version': '3', 'snmpDiscoveryKey': 'SNMPDIS-1730', 'snmpDiscoveryName': 'Anbar-choobiran', 'credentialProfile': 'CRDPF-34'}
    return job_result

def execute_snmp(target_details):
    return_result = []
    device_ipaddress = target_details["device_ipaddress"]
    credential_name = target_details["credential_name"]
    # version = target_details["snmp_version"]
    target_oid = "1.3.6.1.2.1.4.22.1.2"
    current_user = str(getpass.getuser()).split("\\")[-1]
    command = rf'cd C:\Users\{current_user}\CoreInspectAgent\snmpAgent&python main.py -i "{device_ipaddress}" -c "{credential_name}" -o "{target_oid}"'  # -v {version}'
    # print(f"[!] command: {command}")
    output_handle = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = output_handle.communicate()
    output_data = stdout.decode("utf-8")
    # print(f"[!!] output_data: {output_data}", flush=True)
    try:
        json_output = json.loads(output_data)
    except Exception as e:
        json_output = []
    # print(f"[!!] json_output: {json_output}", flush=True)
connectionName
    for item in json_output:
        tmp_target_data = {}
        tmp_target_data = target_details.copy()
        try:
            tmp_target_data["discovered_ip"] = item["oid_data"]
            discovered_mac = item["Value"]
            if discovered_mac.count(" ") < 5:
                try:
                    discovered_mac = discovered_mac.encode("ascii").hex().upper()
                    discovered_mac = ' '.join(discovered_mac[i:i + 2] for i in range(0, len(discovered_mac), 2))
                except Exception as e:
                    pass
            tmp_target_data["discovered_mac"] = discovered_mac
            return_result.append(tmp_target_data.copy())
        except Exception as e:
            pass

    return return_result



job_result = get_network_nodes(coresolution_handle)

current_scanid = coresolution_handle.fetch_global_variables("scanid")

print("[+] Parsing returned data.")
target_results = []
for result in job_result:
    tmp_result = {}

    tmp_result["device_ipaddress"] = result["snmpIpAddress"]
    tmp_result["network_node_key"] = result["_backgroundKey"]
    tmp_result["credential_name"] = result["credName"]
    tmp_result["snmp_version"] = result["version"]
    tmp_result["snmp_discovery_key"] = result["snmpDiscoveryKey"]
    tmp_result["snmp_discovery_name"] = result["snmpDiscoveryName"]
    tmp_result["credential_profile"] = result["credentialProfile"]
    tmp_result["scanid"] = current_scanid

    target_results.append(tmp_result.copy())

print(f"[!] target_results Length: {len(target_results)}")

coresolution_handle.change_global_variable("scanid", "Int", str(int(current_scanid)+1))

all_fetched_data = []
thread_count = 20
print(f"[+] Fetching SNMP data using [{thread_count}] threads.")
pool = ThreadPool(processes=thread_count)
results = []
while target_results:
    target = target_results.pop()
    # print(f"[!] Target: {target}")
    results.append(pool.apply_async(execute_snmp, (target,)))

pool.close()  # Done adding tasks.
pool.join()
returned_data = [result.get() for result in results]
# print(f"[!] returned_data: {returned_data}")
for result in returned_data:
    for data in result:
        all_fetched_data.append(data)

# print(f"[!] all_fetched_data: {all_fetched_data}")

# while len(target_results) > 0:
#     thread_queue = target_results[:thread_count]
#     del target_results[:thread_count]
#
#     executor = concurrent.futures.ThreadPoolExecutor()
#     thread_pool = []
#
#     for target in thread_queue:
#         thread_pool.append(executor.submit(execute_snmp, target))
#
#     returned_data = [f.result() for f in thread_pool]
#     for result in returned_data:
#         for data in result:
#             all_fetched_data.append(data)


print("[+] Creating CSV File.")
all_values = []
headers = ["id", "scanid", "discoverynodeip", "createdtime", "mac", "ip"]
for value in all_fetched_data:
    tmp_value = [
        str(generate_new_GUID()),
        value["scanid"],
        ip_to_decimal(value["device_ipaddress"]),
        current_time(),
        value["discovered_mac"],
        ip_to_decimal(value["discovered_ip"])
    ]
    all_values.append(tmp_value)
output_csv_name = "output.csv"

create_csv(headers, all_values, "data.csv")
print("[+] Inserting into db.")
insert_csv_to_db("data.csv", "network_node_discovery", "arp_table", config_data)
# try:
#     os.remove(output_csv_name)
# except Exception as e:
#     pass
