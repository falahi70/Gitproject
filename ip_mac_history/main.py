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
import argparse


parser = argparse.ArgumentParser(description="ARP Table executer agent.")

parser.add_argument("-i", "--ipaddress",
                    default=False,
                    help='Comma seperated list of target ipaddresses.')

options = parser.parse_args()

ip_list = []
if options.ipaddress:
    for ip in options.ipaddress.split(","):
        ip_list.append(ip)

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


def get_network_nodes():
    print("[+] Fetching data from coresolution.")
    cpl = '''|snippet \"SNMP Discovery\"'''
    job_result = coresolution_handle.execute_cpl(cpl)
    # print(job_result)
    ## Sample Data: {'_backgroundKey': 'SNMPDIS-1730', 'snmpIpAddress': '10.8.70.1', 'credName': 'SNMP-v3-InterVLAN-routing', 'version': '3', 'snmpDiscoveryKey': 'SNMPDIS-1730', 'snmpDiscoveryName': 'Anbar-choobiran', 'credentialProfile': 'CRDPF-34'}
    return job_result

def execute_snmp(target_details):
    return_result = []
    device_ipaddress = target_details["device_ipaddress"]
    credential_name = target_details["credential_name"]
    # version = target_details["snmp_version"]
    target_oid = "1.3.6.1.2.1.4.22.1.2"
    current_user = str(getpass.getuser()).split("\\")[-1]
    command = rf'cd /CoreInspect/agents/snmpAgent;python main.py -i "{device_ipaddress}" -c "{credential_name}" -o "{target_oid}"'  # -v {version}'
    print(f"[!] command: {command}", flush=True)
    output_handle = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = output_handle.communicate()
    output_data = stdout.decode("utf-8")
    # print(f"[!!] output_data: {output_data}", flush=True)
    try:
        json_output = json.loads(output_data)
    except Exception as e:
        json_output = []
    # print(f"[!!] json_output: {json_output}", flush=True)

    for item in json_output:
        tmp_target_data = {}
        tmp_target_data = target_details.copy()
        try:
            tmp_target_data["discovered_ip"] = item["oid_data"]
            discovered_mac = item["Value"]  # 0:c:29:a0:b3:18
            try:
                discovered_mac = discovered_mac.upper()
                discovered_mac = f"0{discovered_mac}" if len(discovered_mac.split(":")[0]) == 1 else discovered_mac
                fixed_discovered_mac = []
                for item in discovered_mac.split(":"):
                    if len(item) < 2:
                        item = f"0{item}"
                        fixed_discovered_mac.append(item)
                    else:
                        fixed_discovered_mac.append(item)
                discovered_mac = " ".join(fixed_discovered_mac)
            except Exception as e:
                pass
            tmp_target_data["discovered_mac"] = discovered_mac
            # print(json.dumps(tmp_target_data))
            # print("-----")
            return_result.append(tmp_target_data.copy())
        except Exception as e:
            pass

    return return_result



job_result = get_network_nodes()

current_scanid = coresolution_handle.fetch_global_variables("Network_Node_Discovery_Scan_Id")

print("[+] Parsing returned data.")
target_results = []
for result in job_result:
    print(job_result)
    tmp_result = {}

    tmp_result["device_ipaddress"] = result["snmpIpAddress"]
    if options.ipaddress:
        if tmp_result["device_ipaddress"] not in ip_list:
            continue
    tmp_result["network_node_key"] = result["_backgroundKey"]
    # tmp_result["credential_name"] = result["connectionName"]
    tmp_result["credential_name"] = result["connectionName"]
    # tmp_result["snmp_version"] = result["version"]
    tmp_result["snmp_discovery_key"] = result["snmpDiscoveryKey"]
    tmp_result["snmp_discovery_name"] = result["snmpDiscoveryName"]
    # tmp_result["credential_profile"] = result["credentialProfile"]
    tmp_result["scanid"] = current_scanid
    target_results.append(tmp_result.copy())

print(f"[!] target_results Length: {len(target_results)}")

coresolution_handle.change_global_variable("Network_Node_Discovery_Scan_Id", "Int", str(int(current_scanid)+1))

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

print(f"[*] All Fetched Data Length: {len(all_fetched_data)}")
if len(all_fetched_data) == 0:
    print("[-] No data fetched from SNMP devices.")
    sys.exit(0)


print("[+] Creating CSV File.")
new_arp_table_data = []
headers = ["id", "discoverynodeip", "mac", "ip", "history", "createdtime", "discoverytype"]
scanid = 0
for value in all_fetched_data:
    default_scan_data = [{"scanid": int(current_scanid), "createdtime": current_time()}]
    tmp_model = {
        "id": generate_new_GUID(),
        "discoverynodeip": ip_to_decimal(value["device_ipaddress"]),
        "mac": value["discovered_mac"],
        "ip": ip_to_decimal(value["discovered_ip"]),
        "createdtime": current_time(),
        "discoverytype": "SNMP",
        "history": json.dumps(default_scan_data)
    }
    new_arp_table_data.append(tmp_model.copy())

print(new_arp_table_data)
print("[*] Getting Host IP data")
try:
    hostip = coresolution_handle.execute_cpl("|snippet \"host ip\"")
except Exception as e:
    print("[-] Failed to get Host IP snippet data.")
    hostip = []

print("[*] Getting VM IP data")
try:
    vmip = coresolution_handle.execute_cpl("|snippet \"vm ip\"")
except Exception as e:
    print("[-] Failed to get VM IP snippet data.")
    vmip = []

for item in hostip:
    default_scan_data = [{"scanid": int(current_scanid), "createdtime": current_time()}]
    tmp_model = {
        "id": generate_new_GUID(),
        "discoverynodeip": item["vcenterIPAddress"],
        "mac": "N/A",
        "ip": item["esxiIPAddress"],
        "createdtime": current_time(),
        "discoverytype": "API",
        "history": json.dumps(default_scan_data)
    }
    new_arp_table_data.append(tmp_model.copy())

for item in vmip:
    default_scan_data = [{"scanid": int(current_scanid), "createdtime": current_time()}]
    tmp_model = {
        "id": generate_new_GUID(),
        "discoverynodeip": item["vcenterIpAddress"],
        "mac": "N/A",
        "ip": item["vmip"],
        "createdtime": current_time(),
        "discoverytype": "API",
        "history": json.dumps(default_scan_data)
    }
    new_arp_table_data.append(tmp_model.copy())

start_time = current_time()

sql_query = "select id, discoverynodeip, mac, ip, history, createdtime, discoverytype from network_node_discovery.arp_table"
database_handle = databaseConnection(
    config_data["database_hostname"],
    config_data["database_username"],
    config_data["database_password"],
    config_data["database_db_name"]
)
current_arp_table_data = database_handle.fetch_sql(sql_query)
triaged_arp_table_data = []
for item in current_arp_table_data:
    tmp_model = {
        "id": item[0],
        "discoverynodeip": item[1],
        "mac": item[2],
        "ip": item[3],
        "history": item[4],
        "createdtime": item[5],
        "discoverytype": item[6]
    }
    triaged_arp_table_data.append(tmp_model.copy())
del current_arp_table_data

new_item = []
updated_items = []
old_items = []
for scan_data in triaged_arp_table_data:
    history = json.loads(scan_data["history"])
    found = False
    for new_arp_data in new_arp_table_data:
        if scan_data["discoverynodeip"] == new_arp_data["discoverynodeip"] and scan_data["ip"] == new_arp_data["ip"] and scan_data["mac"] == new_arp_data["mac"]:
            found = True
            current_db_history = json.loads(scan_data["history"])
            if current_db_history:
                sorted_history = sorted(current_db_history, key=lambda d: d['scanid'])
                if len(current_db_history) > 360:
                    try:
                        current_db_history = current_db_history[-360:]
                    except Exception as e:
                        current_db_history = current_db_history

                last_scan_id = current_db_history[-1]["scanid"]
                # new_scan_data = {"scanid": int(last_scan_id) + 1, "createdtime": current_time()}
                new_scan_data = {"scanid": int(current_scanid), "createdtime": current_time()}
                current_db_history.append(new_scan_data.copy())
                scan_data["history"] = json.dumps(current_db_history)
                updated_items.append(scan_data.copy())
                break
            else:
                new_scan_data = [{"scanid": int(current_scanid), "createdtime": current_time()}]
                scan_data["history"] = json.dumps([new_scan_data])
                updated_items.append(scan_data.copy())
                break

    if not found:
        old_items.append(scan_data.copy())

for new_arp_data in new_arp_table_data:
    found = False
    for scan_data in triaged_arp_table_data:
        if new_arp_data["discoverynodeip"] == scan_data["discoverynodeip"] and new_arp_data["ip"] == scan_data["ip"] and new_arp_data["mac"] == scan_data["mac"]:
            found = True
            break
    if not found:
        new_item.append(new_arp_data.copy())


total_data = new_item + updated_items + old_items
sql_query = "delete from network_node_discovery.arp_table"
database_handle.execute_sql(sql_query)

end_time = current_time()

output_csv_name = "output.csv"

create_csv(headers, total_data, "data.csv")
print("[+] Inserting into db.")
insert_csv_to_db("data.csv", "network_node_discovery", "arp_table", config_data)

print(f"[*] Comparing time: [{start_time}] -> [{end_time}]")

try:
    os.remove(output_csv_name)
except Exception as e:
    pass


