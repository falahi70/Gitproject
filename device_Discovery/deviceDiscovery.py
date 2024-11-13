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
import argparse
import win32file

win32file._setmaxstdio(4096)
urllib3.disable_warnings()
config = load_config()
# paramiko.util.log_to_file('NUL')

parser = argparse.ArgumentParser(description="CoreInspect Device Discovery Agent.")

parser.add_argument("-i", "--ipaddress",
                    default=False,
                    help='Pass your target IP address to debug discovery process.')

parser.add_argument("-t", "--types",
                    default=False,
                    help='Comma,Seperated list of discovery types. (E.x wmi,ssh,snmp,snmpv1). Ignore this switch to discover all types.')

options = parser.parse_args()

debug_ip = True if options.ipaddress else False

if debug_ip and not options.types:
    print("[-] You need to define discovery types using -t or --types switch.")
    print("[!] Example:")
    print("\t- python deviceDiscovery.py -i 1.1.1.1 -t wmi")
    print("\t- python deviceDiscovery.py -i 1.1.1.1 -t wmi,ssh")
    sys.exit(0)
    
if options.types:
    target_types = options.types.split(",")
    target_types = [str(t_type).lower() for t_type in target_types]
else:
    target_types = ["all"]

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

    if debug_ip:
        test_targets = []
        for target in targets:
            if target["ipaddress_string"] == options.ipaddress:
                test_targets.append(target.copy())
        targets = test_targets.copy()



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
    if debug_ip:
        print(f"[!] Targets after PortScan: {targets}")

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
        if debug_ip:
            print(f"[!] Target Credential Name: {credential_name}")
        target_username, target_password = fetch_credential_data(credential_name)
        if debug_ip:
            print(f"[!] User/Pass: {target_username}:{target_password}")
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
        if debug_ip:
            print(f"[!] finalQuery: {finalQuery}")
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
def snmp_discovery(snmp_target_list, config):
    print("[SNMP] Started Discovery Phase.")
    # snmp_data_unparsed = coresolution_handle.execute_cpl(config["snmp_discovery_coresolution_cpl"])

    target_list = []
    for data in snmp_target_list:
        tmp_target = {}
        tmp_target["id"] = generate_new_GUID()
        tmp_target["network_node_key"] = data.get("network_node_key")
        tmp_target["network_node_ipaddress"] = data.get("network_node_ipaddress")
        tmp_target["ipaddress_string"] = data.get("ipaddress_string")
        # tmp_target["credential_profile"] = data.get("credentialProfile")
        tmp_target["credential_name"] = data.get("credential_name")
        # tmp_target["connectiontype"] = data.get("connectiontype")
        if "v2" in tmp_target["credential_name"].lower():
            tmp_target["version"] = 2
        elif "v3" in tmp_target["credential_name"].lower():
            tmp_target["version"] = 3
        else:
            tmp_target["version"] = 1
        tmp_target["domain"] = "N/A"

        target_list.append(tmp_target.copy())

    # del snmp_data_unparsed

    if debug_ip:
        test_targets = []
        for target in target_list:
            if target["ipaddress_string"] == options.ipaddress:
                test_targets.append(target.copy())
        target_list = test_targets.copy()
    # print(f"[!] TargetList Length: {len(target_list)}")

    # target_list = target_list[:20]
    print(f"[SNMP] Targets Length: [{len(target_list)}].")
    print(f"[SNMP] Getting SNMP hostname data. [{current_time()}]")

    returned_snmp_result_hostname = execute_snmp_jobs(
        target_list,
        target_oid=".1.3.6.1.2.1.1.5",
        output_fieldname="hostname",
        check_status=False,
        thread_count=20,
        debug_ip=debug_ip,
        connection_information=target_connection_details)

    # print(returned_snmp_result_hostname)
    # sys.exit(0)

    print(f"[SNMP] Getting SNMP description data. [{current_time()}]")
    returned_snmp_result_hostname_description = execute_snmp_jobs(
        returned_snmp_result_hostname,
        target_oid=".1.3.6.1.2.1.1.1",
        output_fieldname="description",
        check_status=True,
        thread_count=20,
        debug_ip=debug_ip,
        connection_information=target_connection_details)
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


### SNMP Discovery Section ###
def snmp_v1_discovery(scanid, coresolution_handle, config):
    print("[SNMP V1] Started Discovery Phase.")
    snmp_data_unparsed = coresolution_handle.execute_cpl(config["snmpv1_discovery_coresolution_cpl"])

    target_list = []
    for data in snmp_data_unparsed:
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = data.get("network_node_key")
        tmp_target["network_node_ipaddress"] = data.get("networkNodeIPAddress")
        tmp_target["ipaddress_string"] = long2ip(data.get("networkNodeIPAddress"))
        tmp_target["credential_profile"] = data.get("credentialProfile", "N/A")
        tmp_target["credential_name"] = data.get("credName", "N/A")
        tmp_target["version"] = 1
        tmp_target["domain"] = "N/A"

        target_list.append(tmp_target.copy())

    del snmp_data_unparsed

  
    if debug_ip:
        test_targets = []
        for target in target_list:
            if target["ipaddress_string"] == options.ipaddress:
                test_targets.append(target.copy())
        target_list = test_targets.copy()
    # print(f"[!] TargetList Length: {len(target_list)}")

    target_list = target_list[:30]
    print(f"[SNMP] Targets Length: [{len(target_list)}].")
    print(f"[SNMP] Getting SNMP hostname data. [{current_time()}]")
    returned_snmp_result_hostname = execute_snmp_jobs(
        target_list,
        target_oid=".1.3.6.1.2.1.1.5",
        output_fieldname="hostname",
        check_status=False,
        thread_count=20,
        debug_ip=debug_ip)

    # print(returned_snmp_result_hostname)
    # sys.exit(0)

    print(f"[SNMP] Getting SNMP description data. [{current_time()}]")
    returned_snmp_result_hostname_description = execute_snmp_jobs(
        returned_snmp_result_hostname,
        target_oid=".1.3.6.1.2.1.1.1",
        output_fieldname="description",
        check_status=True,
        thread_count=20,
        debug_ip=debug_ip)
    # file_handle = open("dump.json", "w", encoding="utf-8", errors="ignore")
    # json.dump(returned_snmp_result_hostname_description, file_handle)
    # file_handle.close()
    # sys.exit(0)
    return_results = []
    for result_data in returned_snmp_result_hostname_description:
        result_data["scanid"] = scanid
        result_data["createdtime"] = current_time()
        result_data["scan_type"] = "SNMP-V1"
        return_results.append(result_data.copy())
    # print(return_results)
    return return_results


### ILO Discovery Section ###
def ilo_discovery(coresolution_network_nodes, config, thread_count=10, connection_details={}):
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

    # coresolution_network_nodes = coresolution_handle.execute_cpl(config["ilo_discovery_coresolution_cpl"])

    target_list = []
    for network_node in coresolution_network_nodes:
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = network_node["network_node_key"]
        tmp_target["network_node_ipaddress"] = network_node["network_node_ipaddress"]
        tmp_target["ipaddress_string"] = network_node["ipaddress_string"]
        tmp_target["credential_name"] = network_node.get("credential_name", False)

        connection_data = connection_details[tmp_target["credential_name"]]

        tmp_target["username"], tmp_target["password"] = connection_data["username"], connection_data["password"]
        tmp_target["scan_type"] = "ILO"
        tmp_target["ilo_version"] = 5 if "5" in tmp_target["credential_name"] else 4
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


def create_csv(headers, values, outputname):
    output_handle = open(outputname, "w", encoding="utf-8", errors="ignore")

    header_str = ",".join(headers)
    output_handle.write(f"{header_str}\n")

    for data in values:
        tmp_string = ""
        for column in headers:
            write_data = str(data.get(column, "N/A"))
            # write_data = write_data.replace(",", "")
            # write_data = write_data.replace('"', '""')
            tmp_string += f"{write_data};"
        tmp_string = tmp_string[:-1]
        output_handle.write(f"{tmp_string}\n")

    output_handle.close()


### SSH Discovery Section ###
def ssh_discovery(ssh_target_list, config, thread_count=30, connection_details={}):
    def get_ssh_information(target_details):
        print(target_details)
        target_ipaddress = target_details["ipaddress_string"]
        target_port = target_details["open_port"]
        target_username = target_details["credential"]["username"]
        target_password = target_details["credential"]["password"]
        target_command = target_details["query"]
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=target_ipaddress, port=target_port, username=target_username, password=target_password, timeout=5)
        except Exception as e:
            target_details["status"] = -1
            target_details["error"] = str(e).replace(";", "")
            return False

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
            return False

        return target_details.copy()

    print("[*] Started SSH Discovery Phase.")
    # coresolution_network_nodes = coresolution_handle.execute_cpl(config["ssh_discovery_coresolution_cpl"])
    # if len(ssh_target_list) < 1:
    #     # print(f"[-] No network node found.\n[CPL Result] {coresolution_network_nodes}")
    #     return []

    # coresolution_network_nodes = coresolution_network_nodes[:2]
    # tmp_data = {'_backgroundKey': 'NETNOD-977640', 'defaultNetworkNode': 'NETNOD-977640', 'ipAddress': '10.0.13.47',
    #             'credentialProfile': 'CRDPF-38', 'discoveredConnectionMethod': 'ssh', 'openport': 22,
    #             'cred': 'linux-Credential', 'query': 'cat /home/coreinspect/InventoryResult'}
    # coresolution_network_nodes.append(tmp_data)

    target_list = []
    added_ipaddresses = []


    for network_node in ssh_target_list:
        if debug_ip:
            if network_node.get("ipAddress", "0.0.0.0") != options.ipaddress:
                continue
        tmp_target = {}
        tmp_target["id"] = str(generate_new_GUID())
        tmp_target["network_node_key"] = network_node["network_node_key"]
        tmp_target["network_node_ipaddress"] = network_node["network_node_ipaddress"]
        tmp_target["ipaddress_string"] = network_node["ipaddress_string"]
        tmp_target["credential_name"] = network_node["credential_name"]

        if tmp_target["ipaddress_string"] in added_ipaddresses:
            continue
        added_ipaddresses.append(tmp_target["ipaddress_string"])

        connection_information = connection_details[network_node["credential_name"]]
        tmp_target["credential"] = connection_information

        try:
            tmp_target["open_port"] = int(connection_information.get("port", "22"))
        except Exception as e:
            tmp_target["open_port"] = 22


        tmp_target["scan_type"] = "SSH"
        tmp_target["query"] = network_node.get("query", "cat /home/coreinspect/InventoryResult")
        target_list.append(tmp_target.copy())
    # del coresolution_network_nodes


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
    final_results = []
    for result in results:
        data = result.get()
        if data:
            final_results.append(data)
    return final_results


device_discovery_headers = ["id", "network_node_key", "network_node_ipaddress", "ipaddress_string", "credential_profile", "credential_name", "hostname", "domain", "description", "status", "error", "scanid", "createdtime", "scan_type", "history"]
database_handle = databaseConnection(
        config["database_ipaddress"],
        config["database_username"],
        config["database_password"],
        config["database_dbname"]
    )
def handle_scanid_result(new_data, scan_type="SNMP"):
    sql_query = f"select id,network_node_key,network_node_ipaddress,ipaddress_string,credential_profile,credential_name,hostname,domain,description,status,error,scanid,createdtime,scan_type,history from device_discovery.device_discovery where scan_type='{scan_type}'"
    current_dd_table_data = database_handle.fetch_sql(sql_query)

    json_current_dd_table_data = []
    for item in current_dd_table_data:
        tmp_model = {
            "id": item[0],
            "network_node_key": item[1],
            "network_node_ipaddress": item[2],
            "ipaddress_string": item[3],
            "credential_profile": item[4],
            "credential_name": item[5],
            "hostname": item[6],
            "domain": item[7],
            "description": item[8],
            "status": item[9],
            "error": item[10],
            "scanid": item[11],
            "createdtime": item[12],
            "scan_type": item[13],
            "history": item[14]
        }
        json_current_dd_table_data.append(tmp_model.copy())

    current_dd_table_data = json_current_dd_table_data.copy()
    new_snmp_result = new_data.copy()

    new_item = []
    updated_items = []
    old_items = []

    for current_scan_data in current_dd_table_data:
        history = json.loads(current_scan_data["history"])
        found = False
        for new_snmp_data in new_snmp_result:
            if str(current_scan_data.get("ipaddress_string", "0.0.0.0")) == str(new_snmp_data.get("ipaddress_string", "0.0.0.0")) and str(
                    current_scan_data.get("status", "False")) == str(new_snmp_data.get("status", "False")) and str(
                    current_scan_data.get("hostname", "N/A")) == str(new_snmp_data.get("hostname", "N/A")) and str(
                    current_scan_data.get("scan_type", "N/A")) == str(new_snmp_data.get("scan_type", "N/A")) and str(
                    current_scan_data.get("description", "N/A")) == str(new_snmp_data.get("description", "N/A")) and str(
                    current_scan_data.get("domain", "N/A")) == str(new_snmp_data.get("domain", "N/A")) and str(
                    current_scan_data.get("credential_name", "N/A")) == str(new_snmp_data.get("credential_name", "N/A")):
                found = True
                current_db_history = json.loads(current_scan_data["history"])
                if current_db_history:
                    sorted_history = sorted(current_db_history, key=lambda d: d['scanid'])
                    if len(current_db_history) > 360:
                        try:
                            current_db_history = current_db_history[-360:]
                        except Exception as e:
                            current_db_history = current_db_history

                    # last_scan_id = current_db_history[-1]["scanid"]
                    # new_scan_data = {"scanid": int(last_scan_id) + 1, "createdtime": current_time()}
                    new_scan_data = {"scanid": int(current_scanid), "createdtime": current_time()}
                    current_db_history.append(new_scan_data.copy())
                    current_scan_data["history"] = json.dumps(current_db_history)
                    updated_items.append(current_scan_data.copy())
                    break
                else:
                    new_scan_data = [{"scanid": int(current_scanid), "createdtime": current_time()}]
                    current_scan_data["history"] = json.dumps(new_scan_data)
                    updated_items.append(current_scan_data.copy())
                    break

        if not found:
            old_items.append(current_scan_data.copy())

    for new_snmp_data in new_snmp_result:
        found = False
        for scan_data in current_dd_table_data:
            if str(scan_data.get("ipaddress_string", "0.0.0.0")) == str(new_snmp_data.get("ipaddress_string", "0.0.0.0"))\
                    and str(scan_data.get("status", "False")) == str(new_snmp_data.get("status", "False")) and str(scan_data.get("hostname", "N/A")) == str(
                    new_snmp_data.get("hostname", "N/A")) and str(scan_data.get("scan_type", "N/A")) == str(
                    new_snmp_data.get("scan_type", "N/A")) and str(scan_data.get("description", "N/A")) == str(
                    new_snmp_data.get("description", "N/A")) and str(scan_data.get("domain", "N/A")) == str(new_snmp_data.get("domain", "N/A")) and str(
                    scan_data.get("credential_name", "N/A")) == str(new_snmp_data.get("credential_name", "N/A")):
                found = True
                break
        if not found:
            new_scan_data = [{"scanid": int(current_scanid), "createdtime": current_time()}]
            new_snmp_data["history"] = json.dumps(new_scan_data)
            new_item.append(new_snmp_data.copy())

    total_data = new_item + updated_items + old_items

    return total_data

def insert_csv_to_db(output_filename, schema_name, table_name, config_file):
    conn, cursor = database_handle.connect()
    input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
    cursor.copy_expert(f"copy {schema_name}.{table_name} from STDIN with delimiter ';' CSV header quote '`'", input_file_handle)
    conn.commit()
    conn.close()

def json2db(scan_type, insert_data):
    device_discovery_headers = ["id", "network_node_key", "network_node_ipaddress", "ipaddress_string",
                                "credential_profile", "credential_name", "hostname", "domain", "description", "status",
                                "error", "scanid", "createdtime", "scan_type", "history"]
    sql_query = f"delete from device_discovery.device_discovery where scan_type='{scan_type}'"
    database_handle.execute_sql(sql_query)
    output_csv_name = "output.csv"
    create_csv(device_discovery_headers, insert_data, output_csv_name)
    insert_csv_to_db(output_csv_name, "device_discovery", "device_discovery", config)


# insert_csv_to_db("output.csv", "device_discovery", "device_discovery", config)
# sys.exit(0)


coresolution_handle = coresolution(
    config["coresolution_scheme"],
    config["coresolution_ipaddress"],
    config["coresolution_username"],
    config["coresolution_password"]
)
coresolution_handle.authenticate()

current_scanid = int(coresolution_handle.fetch_global_variables("deviceDiscoveryScanId"))
scanid = current_scanid

wmi_target_list = []
snmp_target_list = []
ssh_target_list = []
api_target_list = []
target_connection_names = []
target_connection_details = {}

device_discovery_targets_cpl = "|snippet \"NetworkNode Discovery Not Null\""
target_device_discovery_list = coresolution_handle.execute_cpl(device_discovery_targets_cpl)

candidate_device_discovery_targets_cpl = "|snippet \"NetworkNode Discovery Null\""
candidate_target_device_discovery_list = coresolution_handle.execute_cpl(candidate_device_discovery_targets_cpl)
refactored = []
for item in candidate_target_device_discovery_list:
    target_model = {
        "netnodeKey": item.get("netnodeKey", "N/A"),
        "ipAddress": item.get("ipaddress", "0.0.0.0"),
        "connectionName": item.get("candidateConnections", "N/A"),
        "connectiontype": item.get("connectiontype", "N/A")
    }

    refactored.append(target_model.copy())

# refactored = refactored[:20]
target_device_discovery_list += refactored
print(f"[!] Target Length: {len(target_device_discovery_list)}")

# print(f"{json.dumps(target_device_discovery_list)}")

for target_data in target_device_discovery_list:
    # print(target_data)
    # print("-----")
    # continue
    target_model = {
        "id": generate_new_GUID(),
        "network_node_key": target_data["netnodeKey"],
        "network_node_ipaddress": ip2long(target_data.get("ipAddress", "0.0.0.0")),
        "ipaddress_string": long2ip(ip2long(target_data.get("ipAddress", "0.0.0.0"))),
        "credential_name": target_data["connectionName"],
        "scanid": scanid
    }
    if target_data["connectiontype"] == "SnmpV3s":
        target_model["scan_type"] = "SNMPv3"
        snmp_target_list.append(target_model.copy())
    elif target_data["connectiontype"] == "RestApi":
        target_model["scan_type"] = "ILO"
        api_target_list.append(target_model.copy())
    elif target_data["connectiontype"] == "Ssh":
        target_model["scan_type"] = "SSH"
        ssh_target_list.append(target_model.copy())
    elif target_data["connectiontype"] == "SnmpV1V2s":
        target_model["scan_type"] = "SNMPv2"
        snmp_target_list.append(target_model.copy())
    else:
        # print(f"[!!] {target_model}")
        continue

    if target_data["connectionName"] not in target_connection_names:
        target_connection_names.append(target_data["connectionName"])

for connection in target_connection_names:
    connection_model = {}
    connection_details = coresolution_handle.fetch_connection(connection)
    try:
        credential_name = connection_details["values"]["credential"]["name"]
    except:
        credential_name = False

    for option in connection_details["values"]["options"]:
        connection_model[option["key"].lower()] = option["value"]

    if credential_name:
        credential_data = coresolution_handle.get_credential(credential_name)
        target_username = credential_data.get("username", "")
        target_password = credential_data.get("password", "")
    else:
        target_username = "N/A"
        target_password = "N/A"

    connection_model["credential_name"] = credential_name
    connection_model["username"] = target_username
    connection_model["password"] = target_password

    target_connection_details[connection] = connection_model.copy()


### WMI Discovery Handle ###
# if "wmi" in target_types or "all" in target_types:
#     try:
#         wmi_discovered_devices = wmi_discovery(scanid, coresolution_handle, config, 30)
#         wmi_insert_data = handle_scanid_result(wmi_discovered_devices, "WMI")
#         if debug_ip:
#             print(f"[!] wmi_discovered_devices: {wmi_discovered_devices}")
#         else:
#             json2db("WMI", wmi_insert_data)
#     except Exception as e:
#         print(f"[-] Error in WMI Discovery.\n[Err] {e}")


### SNMP Discovery Handle ###
if "snmp" in target_types or "all" in target_types:
    try:
        snmp_discovery_result = snmp_discovery(snmp_target_list, config)
        snmp_insert_data = handle_scanid_result(snmp_discovery_result, "SNMP")
        if debug_ip:
            print(f"[!] snmp_discovery_result: {snmp_discovery_result}")
        else:
            json2db("SNMP", snmp_insert_data)

    except Exception as e:
        print(f"[-] Error in SNMP Discovery.\n[Err] {e}")
        snmp_insert_data = []


# ### SNMP V1 Discovery Handle ###
# if "snmpv1" in target_types or "all" in target_types:
#     try:
#         snmp_v1_discovery_result = snmp_v1_discovery(scanid, coresolution_handle, config)
#         snmp_v1_insert_data = handle_scanid_result(snmp_v1_discovery_result, "SNMP-V1")
#         if debug_ip:
#             print(f"[!] snmp_discovery_result: {snmp_v1_discovery_result}")
#         else:
#             json2db("SNMP-V1", snmp_v1_insert_data)
#     except Exception as e:
#         print(f"[-] Error in SNMP Discovery.\n[Err] {e}")

### ILO4 Discovery Handle ###
if "ilo" in target_types or "all" in target_types:
    ilo4_discovery_result = ilo_discovery(api_target_list, config, thread_count=10, connection_details=target_connection_details)
    ilo4_insert_data = handle_scanid_result(ilo4_discovery_result, "ILO")
    if debug_ip:
        print(f"[!] ilo4_discovery_result: {ilo4_discovery_result}")
    else:
        json2db("ILO", ilo4_insert_data)
    # try:
    #     ilo4_discovery_result = ilo_discovery(api_target_list, config, target_connection_details)
    #     if debug_ip:
    #         print(f"[!] ilo4_discovery_result: {ilo4_discovery_result}")
    #     else:
    #         bulk2db(ilo4_discovery_result, "dumps\\ilo4.csv", "dumps\\ilo4_dump.json")
    # except Exception as e:
    #     print(f"[-] Error in ILO Discovery.\n[Err] {e}")


### SSH Discovery Handle ###
if "ssh" in target_types or "all" in target_types:

    # refactored_list = []
    # for item in ssh_target_list:
    #     if item["ipaddress_string"] == "192.168.172.85":
    #         refactored_list.append(item.copy())
    # ssh_target_list = refactored_list

    ssh_discovery_result = ssh_discovery(ssh_target_list, config, thread_count=30, connection_details=target_connection_details)
    ssh_insert_data = handle_scanid_result(ssh_discovery_result, "SSH")
    if debug_ip:
        print(f"[!] ssh_discovery_result: {ssh_discovery_result}")
    else:
        json2db("SSH", ssh_insert_data)
    # try:
    #     ssh_discovery_result = ssh_discovery(scanid, coresolution_handle, config)
    #     if debug_ip:
    #         print(f"[!] ssh_discovery_result: {ssh_discovery_result}")
    #     else:
    #         bulk2db(ssh_discovery_result, "dumps\\ssh.csv", "dumps\\ssh_dump.json")
    # except Exception as e:
    #     print(f"[-] Error in SSH Discovery.\n[Err] {e}")


# ### EMC Discovery Handle ###
# if "emc" in target_types or "all" in target_types:
#     try:
#         emc_discovery_result = emc_discovery(scanid, coresolution_handle, config)
#         if debug_ip:
#             print(f"[!] emc_discovery_result: {emc_discovery_result}")
#         else:
#             bulk2db(emc_discovery_result, "dumps\\emc.csv", "dumps\\emc_dump.json")
#     except Exception as e:
#         print(f"[-] Error in EMC Discovery.\n[Err] {e}")


if not debug_ip:
    print("[+] Incrementing [deviceDiscoveryScanId] Global Variable.")
    scanid += 1
    coresolution_handle.change_global_variable("deviceDiscoveryScanId", "Int", str(scanid))

cred_dir = "."
cred_directory_data = os.listdir(cred_dir)

if not debug_ip:
    for item in cred_directory_data:
        if item.endswith(".cred"):
            os.remove(os.path.join(cred_dir, item))
else:
    print("[!] Credentials WAS NOT DELETED! DELETE THEM YOURSELF after the tests.")
