import json
import os.path
import sys
import requests
import urllib3
from modules.portscanner import *
from modules.coresolution import *
from modules.general_functions import *
from modules.snmp_modules import *
from modules.database_connections import *
from modules.emc_modules import *
import ipaddress
import subprocess
import paramiko
from multiprocessing.pool import ThreadPool

urllib3.disable_warnings()
config = load_config()
paramiko.util.log_to_file('NUL')

### WMI Discovery Section ###
wmi_discovery_thread_results = []
def execute_get_result(command, data_object={}):
    global wmi_discovery_thread_results
    error_table = {
        "RPC server is unavailable": "'Error 0x800706ba' or 'RPC server is unavailable'",
        "0x800706ba": "'Error 0x800706ba' or 'RPC server is unavailable'",
        "0x80041032": '"5858" and "Result Code 0x80041032"',
        "WBEM_E_NOT_FOUND": '"Error 0x80041002 (WBEM_E_NOT_FOUND)"',
        "0x80041002 ": '"Error 0x80041002 (WBEM_E_NOT_FOUND)"',
        "No such interface supported": 'No such interface supported',
        "Access denied": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
        "Access is denied": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
        "0x80070005": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
        "0x80041003": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
        "Fatal Error During Installation": '"Error 1603" or "Fatal Error During Installation"',
        "Error 1603": '"Error 1603" or "Fatal Error During Installation"',
        "Timeout Error": '"Timeout Error"',
        "Connection could not be established": '"Failure to Connect" or "Connection could not be established"',
        "Failure to Connect": '"Failure to Connect" or "Connection could not be established"',
        "Generic failure": 'get-WmiObject: "Generic Failure"',
        "Key not valid for use in specified state": 'Specified credential is not valid for current user.'
    }
    print(f"[!] command: {command}", flush=True)
    process_handle = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output, error = process_handle.communicate(timeout=120)
    except:
        output, error = b"Timeout Error.", b"Timeout Error."

    data_object["command"] = command
    result = output.decode(encoding="utf-8", errors="ignore")
    data_object["command_result"] = result
    try:
        json_data = json.loads(result)
        data_object["hostname"] = json_data["Name"]
        # print(data_object["hostname"], flush=True)
        data_object["domain"] = json_data["Domain"]
        data_object["status"] = 1
        data_object["error"] = "N/A"
    except Exception as e:
        wmi_message = str(result)
        # print(wmi_message[:100], flush=True)
        known_error = False
        for error_key, error_details in error_table.items():
            if error_key.lower() in wmi_message.lower():
                data_object["error"] = error_details
                data_object["hostname"] = "N/A"
                data_object["domain"] = "N/A"
                data_object["status"] = -1
                known_error = True
                break
        if not known_error:
            data_object["error"] = "[-] Unknown Error."
            data_object["hostname"] = "N/A"
            data_object["domain"] = "N/A"
            data_object["status"] = -1
    data_object["description"] = "N/A"
    wmi_discovery_thread_results.append(data_object)
    return data_object

port_scan_result = []
def wmi_discovery(scanid, coresolution_handle, config, thread_count):
    global wmi_discovery_thread_results
    global port_scan_result
    print("[WMI] Agent Started.")

    def tcp_single_ip_single_port_scan(target, port):
        global port_scan_result
        port = int(port)
        tmp_target = target.copy()
        target_ipaddress = target["ipaddress_string"]
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(2)
            result = tcp.connect_ex((target_ipaddress, port))
            # print(result)
            if result == 0:
                tmp_target["islive"] = True
            else:
                tmp_target["islive"] = False

            port_scan_result.append(tmp_target.copy())

        except Exception as e:
            print(e)
            sys.exit()

    targets = []
    print("[WMI] Fetching Network Nodes.")
    network_nodes = coresolution_handle.execute_cpl(config["wmi_discovery_coresolution_cpl"])
    for network_node in network_nodes:
        tmp_data = {}
        tmp_data["network_node_key"] = network_node["networkNodeKey"]
        tmp_data["network_node_ipaddress"] = network_node["networkNodeIPAddress"]
        tmp_data["ipaddress_string"] = str(ipaddress.ip_address(int(network_node["networkNodeIPAddress"])))
        tmp_data["credential_profile"] = network_node["credentialProfile"]
        tmp_data["credential_name"] = network_node["cred"]
        targets.append(tmp_data.copy())

    test_targets = []
    for target in targets:
        if target["ipaddress_string"] == "10.8.8.56":
            test_targets.append(target.copy())
    targets = test_targets.copy()
    print(f"[!] targets: {targets}", flush=True)

    # targets = targets[:20]
    # target1 = {'network_node_key': 'NETNOD-938370', 'network_node_ipaddress': 168431130, 'ipaddress_string': '10.10.14.26', 'credential_profile': 'CRDPF-36', 'credential_name': 'WMI-Credential'}
    # target2 = {'network_node_key': 'NETNOD-938370', 'network_node_ipaddress': 167781695, 'ipaddress_string': '10.0.37.63', 'credential_profile': 'CRDPF-36', 'credential_name': 'WMI-Credential'}
    # targets = [target1, target2]
    print(f"[WMI] Network Nodes Length: [{len(targets)}]")
    print(f"[WMI] Running Port Scan. ({current_time()})")

    portscan_thread_count = int(len(targets)/4)
    if portscan_thread_count < 1:
        portscan_thread_count = 1
    pool = ThreadPool(processes=portscan_thread_count)
    results = []
    while (targets):
        target = targets.pop()
        results.append(pool.apply_async(tcp_single_ip_single_port_scan, (target, 135,)))

    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete.
    print(f"[WMI] Finished Port Scan. ({current_time()})")

    targets = port_scan_result
    print(f"[!] After Port Scan targets: {targets}", flush=True)
    del port_scan_result

    wmi_thread_count = int(thread_count)
    # targets = targets[:50]
    live_addresses = 0
    for target in targets:
        if target["islive"]:
            live_addresses += 1

    print(f"[WMI] WMI Targets: [{live_addresses}]")

    pool = ThreadPool(processes=wmi_thread_count)
    results = []

    print(f"[WMI] Discovery Threads Started. ({current_time()})")
    fetched_credentials = {}
    def fetch_credential_data(credential_name):
        if credential_name not in fetched_credentials.keys():
            credential_data = coresolution_handle.get_credential(credential_name)
            if credential_data:
                target_username = credential_data["username"]
                target_password = credential_data["password"]
            else:
                target_username = False
                target_password = False
            fetched_credentials[credential_name] = {"username": target_username,
                                                    "password": target_password}
        else:
            target_username = fetched_credentials[credential_name]["username"]
            target_password = fetched_credentials[credential_name]["password"]
        return target_username, target_password

    while (targets):
        target = targets.pop()
        target["id"] = str(generate_new_GUID())
        target["createdtime"] = current_time()
        target["scanid"] = scanid
        target["scan_type"] = "WMI"

        if not target["islive"]:
            target["error"] = "[-] Port 135 Is Closed."
            target["status"] = -1
            results.append(target.copy())
            continue
        credential_name = target['credential_name']
        print(f"[!] Credential Name: {credential_name}", flush=True)
        target_username, target_password = fetch_credential_data(credential_name)
        print(f"[!] User/Pass: {target_username} {target_password}")
        if not target_username and not target_password:
            target["error"] = "[-] Port 135 Is Closed."
            target["status"] = -1
            results.append(target.copy())
            continue

        if not os.path.exists(f"{credential_name}.cred"):
            file_handle = open(f"{credential_name}.cred", "w", encoding="utf-8", errors="ignore")
            file_handle.write(target_password)
            file_handle.close()
        target_address = target['ipaddress_string']

        finalQuery = f"powershell -c \"$passtxt=Get-Content {credential_name}.cred;$password = convertto-securestring -String $passtxt -AsPlainText -Force;$username='{target_username}';$credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password);get-WmiObject -Query 'select Name, Domain from win32_computersystem' -ComputerName {target_address} -Credential $credential | Select-Object Name, Domain | ConvertTo-Json\""
        results.append(pool.apply_async(execute_get_result, (finalQuery, target, ),))

    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete.
    # results = [result.get() for result in results]
    print(f"[WMI] Discovery Threads Finished. ({current_time()})")
    final_results = []
    for result in wmi_discovery_thread_results:
        final_results.append(result.copy())

    return final_results


### SNMP Discovery Section ###
def snmp_discovery(scanid, coresolution_handle, config):
    print("[SNMP] Started Discovery Phase.")
    snmp_data_unparsed = coresolution_handle.execute_cpl(config["snmp_discovery_coresolution_cpl"])

    target_list = []
    for data in snmp_data_unparsed:
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = data.get("networkNodeKey")
        tmp_target["network_node_ipaddress"] = data.get("networkNodeIPAddress")
        tmp_target["ipaddress_string"] = long2ip(data.get("networkNodeIPAddress"))
        tmp_target["credential_profile"] = data.get("credentialProfile")
        tmp_target["credential_name"] = data.get("credName")
        tmp_target["version"] = int(str(data.get("credType"))[-1])
        tmp_target["domain"] = "N/A"

        target_list.append(tmp_target.copy())

    del snmp_data_unparsed

    test_targets = []
    for target in target_list:
        if target["ipaddress_string"] in ["10.0.8.33", "10.0.8.35","10.8.26.55","10.8.26.56","10.8.26.57","10.8.26.58","10.6.8.16","10.6.8.17"]:
            test_targets.append(target.copy())
    target_list = test_targets.copy()
    print(f"[!] target_list: {target_list}")
    # print(f"[!] TargetList Length: {len(target_list)}")

    # target_list = target_list[:20]
    print(f"[SNMP] Targets Length: [{len(target_list)}].")
    print(f"[SNMP] Getting SNMP hostname data. [{current_time()}]")
    returned_snmp_result_hostname = execute_snmp_jobs(
        target_list,
        target_oid=".1.3.6.1.2.1.1.5",
        output_fieldname="hostname",
        check_status=False,
        thread_count=20)

    # print(returned_snmp_result_hostname)
    # sys.exit(0)

    print(f"[SNMP] Getting SNMP description data. [{current_time()}]")
    returned_snmp_result_hostname_description = execute_snmp_jobs(
        returned_snmp_result_hostname,
        target_oid=".1.3.6.1.2.1.1.1",
        output_fieldname="description",
        check_status=True,
        thread_count=20)
    # file_handle = open("dump.json", "w", encoding="utf-8", errors="ignore")
    # json.dump(returned_snmp_result_hostname_description, file_handle)
    # file_handle.close()
    # sys.exit(0)
    return_results = []
    for result_data in returned_snmp_result_hostname_description:
        result_data["scanid"] = scanid
        result_data["createdtime"] = current_time()
        result_data["scan_type"] = "SNMP"
        return_results.append(result_data.copy())
    # print(return_results)
    return return_results


### ILO Discovery Section ###
def ilo_discovery(scanid, coresolution_handle, config, thread_count=10):
    print("[*] Started ILO Discovery Phase.")
    def get_lio4_information(target_details):
        target_ipaddress = target_details["ipaddress_string"]
        target_username = target_details["username"]
        target_password = target_details["password"]
        request_url = f"https://{target_ipaddress}/rest/v1/managers/1/ethernetinterfaces/1"
        try:
            response_handle = requests.get(request_url, auth=(target_username, target_password), verify=False, timeout=10)
        except Exception as e:
            target_details["hostname"] = "N/A"
            target_details["description"] = "N/A"
            target_details["domain"] = "N/A"
            target_details["status"] = -1
            target_details["error"] = "Timeout happened."
            return target_details.copy()

        if int(response_handle.status_code) == 200:
            response_json = response_handle.json()
            target_details["hostname"] = response_json.get("HostName", "N/A")
            target_details["description"] = response_json.get("FactoryMacAddress", "N/A")
            target_details["domain"] = "N/A"
            target_details["status"] = 1
            return target_details.copy()
        else:
            target_details["hostname"] = "N/A"
            target_details["description"] = "N/A"
            target_details["domain"] = "N/A"
            target_details["status"] = -1
            error_msg = str(response_handle.text)
            error_msg = error_msg.replace("\n", "")[:500]
            target_details["error"] = error_msg
            return target_details.copy()

    def get_lio5_information(target_details):
        target_ipaddress = target_details["ipaddress_string"]
        target_username = target_details["username"]
        target_password = target_details["password"]
        request_url = f"https://{target_ipaddress}/redfish/v1/managers/1/ethernetinterfaces/1"
        try:
            response_handle = requests.get(request_url, auth=(target_username, target_password), verify=False, timeout=10)
        except Exception as e:
            target_details["hostname"] = "N/A"
            target_details["description"] = "N/A"
            target_details["domain"] = "N/A"
            target_details["status"] = -1
            target_details["error"] = "Timeout happened."
            return target_details.copy()

        if int(response_handle.status_code) == 200:
            response_json = response_handle.json()
            target_details["hostname"] = response_json.get("HostName", "N/A")
            target_details["description"] = response_json.get("FactoryMacAddress", "N/A")
            target_details["domain"] = "N/A"
            target_details["status"] = 1
            return target_details.copy()
        else:
            target_details["hostname"] = "N/A"
            target_details["description"] = "N/A"
            target_details["domain"] = "N/A"
            target_details["status"] = -1
            error_msg = str(response_handle.text)
            error_msg = error_msg.replace("\n", "")[:500]
            target_details["error"] = error_msg
            return target_details.copy()

    coresolution_network_nodes = coresolution_handle.execute_cpl(config["ilo_discovery_coresolution_cpl"])

    target_list = []
    for network_node in coresolution_network_nodes:
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = network_node.get("networkNodeKey", "N/A")
        tmp_target["network_node_ipaddress"] = network_node.get("ipaddress", "0.0.0.0")
        tmp_target["ipaddress_string"] = network_node.get("iloIpAddress", "0.0.0.0")
        tmp_target["discovery_state"] = network_node.get("webApplicationDiscovery", "N/A")
        tmp_target["credential_profile"] = network_node.get("credentialProfile", "N/A")
        tmp_target["credential_name"] = network_node.get("cred", "N/A")
        credential_data = coresolution_handle.get_credential(tmp_target["credential_name"])
        tmp_target["username"], tmp_target["password"] = credential_data["username"], credential_data["password"]
        tmp_target["scan_type"] = "ILO"
        tmp_target["ilo_version"] = 5 if "5" in tmp_target["discovery_state"] else 4
        target_list.append(tmp_target.copy())
    del coresolution_network_nodes

    pool = ThreadPool(processes=thread_count)
    results = []
    started = current_time()
    print(f"[ILO] Threads jobs started. ({started})")

    while (target_list):
        target_details = target_list.pop()
        target_details["scanid"] = scanid
        target_details["createdtime"] = current_time()
        if target_details["ilo_version"] == 4:
            results.append(pool.apply_async(get_lio4_information,
                                            (target_details.copy(),)))
        else:
            results.append(pool.apply_async(get_lio5_information,
                                            (target_details.copy(),)))
    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete.
    print(f"[ILO] Threads jobs Finished. ({current_time()})")
    results = [result.get() for result in results]

    return results


### EMC Discovery Section ###
def emc_discovery(scanid, coresolution_handle, config, thread_count=10):
    print("[*] Started EMC Discovery Phase.")
    def get_emc_information(target_details):
        target_ipaddress = target_details["ipaddress_string"]
        credential_name = target_details["credential_name"]

        conn, cursor = db_connect()
        db_query = f"select username, \"string\" from asset_inventory.clixml where name='{credential_name}';"
        cursor.execute(db_query)
        try:
            target_username, target_password = cursor.fetchall()[0]
            conn.close()
        except Exception as e:
            print(f"[-] Failed To Fetch Credentials.\n[Query] {db_query}")
            target_details["status"] = -1
            target_details["error"] = str(e)
            return target_details.copy()

        try:
            emc_name, emc_model = get_emc_general_data(target_ipaddress, target_username, target_password)
            target_details["hostname"] = emc_name
            target_details["description"] = emc_model
            target_details["domain"] = "N/A"
            target_details["status"] = 1
        except Exception as e:
            target_details["status"] = -1
            target_details["error"] = str(e)

        return target_details.copy()

    coresolution_network_nodes = coresolution_handle.execute_cpl(config["emc_discovery_coresolution_cpl"])

    target_list = []
    unique_hostname_check = []
    for network_node in coresolution_network_nodes:
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = network_node.get("networkNodeKey", "N/A")
        tmp_target["network_node_ipaddress"] = ip2long(network_node.get("ipaddress", "0.0.0.0"))
        tmp_target["ipaddress_string"] = network_node.get("ipaddress", "0.0.0.0")
        tmp_target["credential_name"] = network_node.get("cred", "N/A")
        tmp_target["scan_type"] = "EMC"
        # print(tmp_target)
        if tmp_target["network_node_ipaddress"] not in unique_hostname_check:
            unique_hostname_check.append(tmp_target["network_node_ipaddress"])
            target_list.append(tmp_target.copy())
    del coresolution_network_nodes

    pool = ThreadPool(processes=thread_count)
    results = []
    started = current_time()
    print(f"[EMC] Threads jobs started. ({started})")

    while (target_list):
        target_details = target_list.pop()
        target_details["scanid"] = scanid
        target_details["createdtime"] = current_time()
        results.append(pool.apply_async(get_emc_information,
                                        (target_details.copy(),)))
    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete.
    print(f"[EMC] Threads jobs Finished. ({current_time()})")
    results = [result.get() for result in results]

    return results


### SSH Discovery Section ###
def ssh_discovery(scanid, coresolution_handle, config, thread_count=30):
    def get_ssh_information(target_details):
        target_ipaddress = target_details["ipaddress_string"]
        target_username = coresolution_handle.get_credential(target_details["credential_name"])["username"]
        target_password = coresolution_handle.get_credential(target_details["credential_name"])["password"]
        target_command = target_details["query"]
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ipaddress, username=target_username, password=target_password, timeout=5)
        except Exception as e:
            target_details["status"] = -1
            target_details["error"] = str(e)
            return target_details.copy()

        try:
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(target_command)
            command_output = ssh_stdout.read().decode(encoding="utf-8", errors="ignore")
            command_output = json.loads(command_output)
            ssh.close()
            target_details["status"] = 1
            target_details["hostname"] = command_output["computerSystem"].get("hostname", "N/A")
            target_details["domain"] = command_output["computerSystem"].get("domain", "N/A")
            target_details["description"] = command_output["computerSystem"].get("osMachineId", "N/A")
        except Exception as e:
            target_details["status"] = -1
            target_details["error"] = str(e)

        return target_details.copy()

    print("[*] Started SSH Discovery Phase.")
    coresolution_network_nodes = coresolution_handle.execute_cpl(config["ssh_discovery_coresolution_cpl"])
    if len(coresolution_network_nodes) < 1:
        print(f"[-] No network node found.\n[CPL Result] {coresolution_network_nodes}")
        return []

    # coresolution_network_nodes = coresolution_network_nodes[:2]
    # tmp_data = {'_backgroundKey': 'NETNOD-977640', 'defaultNetworkNode': 'NETNOD-977640', 'ipAddress': '10.0.13.47',
    #             'credentialProfile': 'CRDPF-38', 'discoveredConnectionMethod': 'ssh', 'openport': 22,
    #             'cred': 'linux-Credential', 'query': 'cat /home/coreinspect/InventoryResult'}
    # coresolution_network_nodes.append(tmp_data)

    target_list = []
    added_ipaddresses = []
    for network_node in coresolution_network_nodes:
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = network_node.get("defaultNetworkNode", "N/A")
        tmp_target["network_node_ipaddress"] = ip2long(network_node.get("ipAddress", "0"))
        tmp_target["ipaddress_string"] = network_node.get("ipAddress", "0.0.0.0")
        if tmp_target["ipaddress_string"] in added_ipaddresses:
            continue
        added_ipaddresses.append(tmp_target["ipaddress_string"])
        tmp_target["credential_profile"] = network_node.get("credentialProfile", "N/A")
        tmp_target["open_port"] = network_node.get("openport", "22")
        tmp_target["credential_name"] = network_node.get("cred", "N/A")
        tmp_target["scan_type"] = "SSH"
        tmp_target["query"] = network_node.get("query", "cat /home/coreinspect/InventoryResult")
        target_list.append(tmp_target.copy())
    del coresolution_network_nodes


    pool = ThreadPool(processes=thread_count)
    results = []
    started = current_time()
    print(f"[SSH] Threads jobs started. ({started})")

    while (target_list):
        target_details = target_list.pop()
        target_details["scanid"] = scanid
        target_details["createdtime"] = current_time()
        results.append(pool.apply_async(get_ssh_information,
                                        (target_details.copy(),)))
    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete.
    print(f"[SSH] Threads jobs Finished. ({current_time()})")
    results = [result.get() for result in results]
    return results


coresolution_handle = coresolution(
    config["coresolution_scheme"],
    config["coresolution_ipaddress"],
    config["coresolution_username"],
    config["coresolution_password"]
)
coresolution_handle.authenticate()

current_scanid = int(coresolution_handle.fetch_global_variables("deviceDiscoveryScanId"))
scanid = current_scanid

# ### WMI Discovery Handle ###
# try:
#     wmi_discovered_devices = wmi_discovery(scanid, coresolution_handle, config, 30)
#     print(wmi_discovered_devices)
#     # bulk2db(wmi_discovered_devices, "dumps\\wmi.csv", "dumps\\wmi_dump.json")
# except Exception as e:
#     print(f"[-] Error in WMI Discovery.\n[Err] {e}")

### SNMP Discovery Handle ###
try:
    snmp_discovery_result = snmp_discovery(scanid, coresolution_handle, config)
    print(f"[!] snmp_discovery_result: {snmp_discovery_result}")
    # bulk2db(snmp_discovery_result, "dumps\\snmp.csv", "dumps\\snmp_dump.json")
except Exception as e:
    print(f"[-] Error in SNMP Discovery.\n[Err] {e}")

# ### ILO4 Discovery Handle ###
# try:
#     ilo4_discovery_result = ilo_discovery(scanid, coresolution_handle, config)
#     bulk2db(ilo4_discovery_result, "dumps\\ilo4.csv", "dumps\\ilo4_dump.json")
# except Exception as e:
#     print(f"[-] Error in ILO Discovery.\n[Err] {e}")


# ### SSH Discovery Handle ###
# try:
#     ssh_discovery_result = ssh_discovery(scanid, coresolution_handle, config)
#     bulk2db(ssh_discovery_result, "dumps\\ssh.csv", "dumps\\ssh_dump.json")
# except Exception as e:
#     print(f"[-] Error in SSH Discovery.\n[Err] {e}")
#
# ### EMC Discovery Handle ###
# try:
#     emc_discovery_result = emc_discovery(scanid, coresolution_handle, config)
#     bulk2db(emc_discovery_result, "dumps\\emc.csv", "dumps\\emc_dump.json")
# except Exception as e:
#     print(f"[-] Error in EMC Discovery.\n[Err] {e}")


# print("[+] Incrementing [deviceDiscoveryScanId] Global Variable.")
# scanid += 1
# coresolution_handle.change_global_variable("deviceDiscoveryScanId", "Int", str(scanid))

cred_dir = "."
cred_directory_data = os.listdir(cred_dir)

for item in cred_directory_data:
    if item.endswith(".cred"):
        os.remove(os.path.join(cred_dir, item))
