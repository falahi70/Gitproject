import sys

from modules.coresolution_api_calls import *
from modules.database_connections import *
from modules.general_functions import *
import json
from modules.coresolution import *
import os

def load_config():
    config_file = json.load(open("appsettings.json", "r", encoding="utf-8", errors="ignore"))
    return config_file

config_data = load_config()

cpl = r'''|   search      resourcetype        =   "snmpDiscovery"
            and status              =   "Enabled"
|   fields  key         as  snmpDiscoveryKey,
            name        as  snmpDiscoveryName,
            ipAddress   as  snmpIpAddress,
            portNumber  as  snmpPortNumber,
            @credential as  snmpCredential
|join               @outer.snmpCredential=@inner.credName
                    [
                        |search     resourcetype ="credentialProfile"
                                and credType ~  "SNMP"
                        |fields     key as  credentialProfile,
                                    name    as  credName,
                                    credType
                    ]
|eval               snmpIpAddress:=longtoip(snmpIpAddress),
                    version:=case(  credType = "SNMP v3" , "3",
                                    credType = "SNMP v2" , "2",
                                    credType = "SNMP v1" , "1"),
                  command                 := "cd snmpAgent;python main.py -i " +snmpIpAddress+ " -c "+ credName +" -o "+$snmpDiscoveryArpOid1$ +" -v "+ version

| snippet "send_command_to_remote_commander"
|spath  input := result  path := "[]" output :=  item
|mvexpand   item
|search     result != null
|fields     -result
|spath  input := item  path := "oid_data" output := networkNodeIpAddress:string
|spath  input := item  path := "Value" output := macAddress:string
|fields     _item.snmpDiscoveryKey as  discoveryNode,
            networkNodeIpAddress,
            macAddress, _item.snmpIpAddress as scannedip
| eval  scanid := $scanid$+1
'''.replace("\n", "")

print("[+] Fetching data from coresolution.")

coresolution_handle = coresolution(
    config_data["coresolution_schema"],
    config_data["coresolution_ipaddress"],
    config_data["coresolution_username"],
    config_data["coresolution_password"])
coresolution_handle.authenticate()
job_result = coresolution_handle.execute_cpl(cpl)  # [{'discoveryNode': 'SNMPDIS-1067', 'networkNodeIpAddress': '10.67.0.22', 'macAddress': '60 73 5C 56 73 84', 'scannedip': '10.9.38.81', 'scanid': 284}]
current_scanid = coresolution_handle.fetch_global_variables("scanid")

target_results = []
for result in job_result:
    tmp_result = {}
    result_netnode_ipaddress = result["networkNodeIpAddress"]
    result_mac_address = result["macAddress"]
    result_scannedip = result["scannedip"]

    tmp_result["scanid"] = current_scanid
    try:
        tmp_result["ipaddress"] = ip_to_decimal(result_netnode_ipaddress)
    except Exception as e:
        tmp_result["ipaddress"] = 0
    tmp_result["mac"] = result_mac_address
    try:
        tmp_result["ip"] = ip_to_decimal(result_scannedip)
    except Exception as e:
        tmp_result["ip"] = 0

    target_results.append(tmp_result.copy())

coresolution_handle.change_global_variable("scanid", "Int", str(int(current_scanid)+1))

print("[+] Creating CSV File.")
all_values = []
headers = ["id", "scanid", "discoverynodeip", "createdtime", "mac", "ip"]
for value in target_results:
    tmp_value = [
        str(generate_new_GUID()),
        value["scanid"],
        value["ipaddress"],
        current_time(),
        value["mac"],
        value["ip"],
    ]
    all_values.append(tmp_value)
output_csv_name = "output.csv"

create_csv(headers, all_values, "data.csv")
insert_csv_to_db("data.csv", "network_node_discovery", "arp_table", config_data)
try:
    os.remove(output_csv_name)
except Exception as e:
    print("[-] Failed To Remove The Output File.")
