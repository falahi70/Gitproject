import sys

from modules.coresolution import *
from modules.database_connections import *
from modules.general_functions import *
import json
from multiprocessing.pool import ThreadPool
from datetime import datetime
import subprocess
import re

start = datetime.now()

database_handle = databaseConnection(
    config["database_connection"]["database_hostname"],
    config["database_connection"]["database_username"],
    config["database_connection"]["database_password"],
    config["database_connection"]["database_dbname"]
)

coresolution_handle = coresolution(
    config["coresolution_connection"]["scheme"],
    config["coresolution_connection"]["address"],
    config["coresolution_connection"]["username"],
    config["coresolution_connection"]["password"]
)
fetched_credentials = {}
targets_with_snmp_result = []
all_network_data = []
matched_temp_network_data = []
Errors = []
osfamily = "IOS"
scanid = database_handle.get_max_scanid_by_osfamily('asset_inventory', 'networkAdapterConfiguration', osfamily)
scanid = str(int(scanid) + 1)

coresolution_handle.authenticate()

targets = coresolution_handle.execute_cpl("""
                    |   search      resourceType        =   "device"
                                and @credential         !=  null
                    |   fields      key                     as      devicekey,
                                    defaultNetworkNode      as      deviceDefaultNetworkNode,
                                    hostname,
                                    operatingSystemtype     as      os,
                                    @credential            
                    |   join            Type := left 
                                        @outer.@credential = @inner.credentialName
                                    [
                                        |   search      resourceType    =   "credentialProfile"               
                                        |   fields      key     as  credentialProfile,
                                                        name            as  credentialName,
                                                        credType
                                    ]
                    |   search      credType ~ "snmp"
                    |   sort        hostname
                    |   eval        snmpVersion         :=  case    (   credType    ~   "v1"    ,   "1",
                                                                        credType    ~   "v2"    ,   "2",
                                                                        credType    ~   "v3"    ,   "3"    )
                    |   join            Type := left 
                                        @outer.deviceDefaultNetworkNode = @inner.networkNodeKey
                                    [
                                        |search         resourceType    =   "networkNode"
                                        |fields         key             as  networkNodeKey,
                                                        ipAddress
                                    ]            
                    |   eval        ipAddress   :=  longtoip(ipAddress)
                    |   fields      hostname,ipAddress,credentialProfile,credentialName,snmpVersion,hostname,os

                                            """)

ips = ["10.0.8.33","10.0.8.35","10.8.26.55","10.8.26.56","10.8.26.57","10.8.26.58","10.6.8.16","10.6.8.17"]
chosen_targets = []
for target in targets:
    if target["ipAddress"] in ips:
        chosen_targets.append(target)
targets = chosen_targets

print("[+] Device Targets Fetched Successfully.")


def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def get_all_credentials():
    global fetched_credentials
    conn, cursor = database_handle.connect()
    def fetch_credential_data(credential_name):
        if credential_name not in fetched_credentials.keys():
            syntax = f"Select username, authenticationphrase, authenticationtype, encryptionphrase, encryptiontype from asset_inventory.clixml where \"name\"='{credential_name}'"
            try:
                cursor.execute(syntax)
            except Exception as e:
                print("[-] Failed To Fetch Credentials From Database.")
                print(f"\t[Err] {e}")
                sys.exit(0)
            try:
                credential_data = cursor.fetchall()#[0]
                try:
                    fetched_credentials[credential_name] = {
                        "username": credential_data[0][0] if credential_data[0][0] != "-" else "",
                        "authenticationphrase": credential_data[0][1] if credential_data[0][1] != "-" else "",
                        "authenticationtype": credential_data[0][2] if credential_data[0][2] != "-" else "",
                        "encryptionphrase": credential_data[0][3] if credential_data[0][3] != "-" else "",
                        "encryptiontype": credential_data[0][4] if credential_data[0][4] != "-" else ""
                    }
                except Exception as e:
                    print("[-] Failed in assigning credential data.")
                    print(f"\t[Err] {e}")
            except Exception as e:
                print("[-] No Credential Found With Provided Name.")
                print(f"\t[Err] {e}")
            if fetched_credentials[credential_name]["username"] == "userName in CoreDynamix":
                try:
                    credential_handle = coresolution_handle.get_credential(credential_name)
                    username = credential_handle["username"]
                    password = credential_handle["password"]
                    fetched_credentials[credential_name]["username"] = username
                except Exception as e:
                    pass

    for target in targets:
        fetch_credential_data(target["credentialName"])
    conn.close()
    print("[+] Credentials Fetched Successfully.\n")
    print(fetched_credentials)

def get_oid(start_oid):
    try:
        new_oid_incrementor = int(start_oid.rsplit(".", 1)[-1]) + 1
        end_oid = f'{start_oid.rsplit(".", 1)[0]}.{new_oid_incrementor}'
    except Exception as e:
        print("[-] Invalid OID Provided.")
        sys.exit(0)
    return start_oid, end_oid


def return_json_line(line, oid):
    line = line.split(", ", 2)
    data_dict = {}
    if oid[0] != ".":
        oid = "." + oid + "."
    else:
        oid += "."
    try:
        for data in line:
            key_value = data.split("=")
            key = key_value[0]
            value = key_value[1]
            while value[0] == " ":
                value = value[1:]
            data_dict[key] = value
            if key == "OID":
                """                
                oid_data = value.rsplit(".", 4)
                oid_data = f"{oid_data[-4]}.{oid_data[-3]}.{oid_data[-2]}.{oid_data[-1]}"
                """
                data_dict["oid_data"] = data_dict[key].replace(oid, "")

    except Exception as e:
        return {}
    return data_dict


def get_snmp_data(target, oid):
    global fetched_credentials, command
    snmp_data = []
    ipaddress = target["ipAddress"]
    start_oid, end_oid = get_oid(oid)
    liseted_result = []
    listed_snmp_results = []

    if target["snmpVersion"] == '3':
        fetched_credentials[target["credentialName"]]["encryptiontype"]
        username = fetched_credentials[target["credentialName"]]["username"]
        authentication_phrase = fetched_credentials[target["credentialName"]]["authenticationphrase"]
        authentication_type = fetched_credentials[target["credentialName"]]["authenticationtype"]
        encryption_phrase = fetched_credentials[target["credentialName"]]["encryptionphrase"]
        encryption_type = fetched_credentials[target["credentialName"]]["encryptiontype"]
        command = fr'SnmpWalk.exe -r:"{ipaddress}" -v:3 -sn:"{username}" -ap:"{authentication_type}" -aw:"{authentication_phrase}" -pp:"{encryption_type}" -pw:"{encryption_phrase}" -os:"{start_oid}" -op:"{end_oid}"'

    if target["snmpVersion"] == '2':
        community = fetched_credentials[target["credentialName"]]["username"]
        command = fr'SnmpWalk.exe -v:{target["snmpVersion"]} -r:"{ipaddress}" -c:"{community}" -os:"{start_oid}" -op:"{end_oid}"'

    if target["snmpVersion"] == '1':
        command = fr'SnmpWalk.exe -r:"{ipaddress}" -os:"{start_oid}" -op:"{end_oid}"'

    try:
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        print(output)
    except Exception as e:
        error = f"[-] Failed run snmpwalk for {ipaddress} and oid: {start_oid} \n\t[Err] {e}\n\t\t{output.stderr.decode()}"
        # print(error)
        Errors.append({
            "hostname": target["hostname"],
            "ip": ipaddress,
            "cred": target["credentialName"],
            "os": target["os"],
            "error": error
        })
    for line in output.stdout.splitlines():
        line = line.decode("utf-8")
        line = line.strip()
        if "Failed to get value of SNMP variable. Timeout." in line:
            error = f"[-] Failed to get value of SNMP variable for {ipaddress} and oid: {start_oid} \n\t[Err] {e}\n\t\t{output.stderr.decode()}"
            print(error)
            Errors.append({
                "hostname": target["hostname"],
                "ip": ipaddress,
                "cred": target["credentialName"],
                "os": target["os"],
                "error": error
            })
            return ["Failed to get value of SNMP variable. Timeout."]
        if "," not in line and "=" not in line:
            continue
        data = return_json_line(line, oid)
        if len(data) > 0:
            snmp_data.append(data)

    if not (isinstance(snmp_data, list)):
        liseted_result.append(listed_snmp_results)
        listed_snmp_results = liseted_result
    else:
        listed_snmp_results = snmp_data

    #print(snmp_data)
    return snmp_data


def snmp_and_match_data(target, oid):
    global targets_with_snmp_result
    snmp_result = get_snmp_data(target, oid)
    target_with_snmp_result = {
        "hostname": target["hostName"],
        "ip": target["ipAddress"],
        "os": target["os"],
        "result": snmp_result
    }
    # print(target_with_snmp_result,snmp_result)
    targets_with_snmp_result.append(target_with_snmp_result)


def threat_snmp_and_match_data(targets, snmp_oid, name):
    print(f"[*] Getting {name} data.")
    print("============>>", targets)
    # number_of_targets = int(len(targets))
    thread_count = 200  # int(number_of_targets / 8)
    pool = ThreadPool(processes=thread_count)
    for target in targets:
        pool.apply_async(snmp_and_match_data, (target, snmp_oid,))
    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete. Total
    print(f"[+] Data fetched for: {name}.")


def match_data(unmatched_data_list, unmatched_comparing_field, hostname_matched_of_all_network_data_list,
               hostname_matched_comparing_field, oid_name, adding_data):
    global matched_temp_network_data
    while (unmatched_data_list):
        # unmatched_data
        unmatched_data = unmatched_data_list.pop()
        for index, i in enumerate(hostname_matched_of_all_network_data_list):
            if (unmatched_data[unmatched_comparing_field]).strip() == (i[hostname_matched_comparing_field]).strip():
                hostname_matched_of_all_network_data_list.pop(index)
                i[oid_name] = (unmatched_data[adding_data]).strip()
                matched_temp_network_data.append(i)

    for i in hostname_matched_of_all_network_data_list:
        i[oid_name] = "-"
        matched_temp_network_data.append(i)


def interfaceindex():
    global targets_with_snmp_result, all_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = "1.3.6.1.2.1.2.2.1.1"
    oid_name = "interfaceindex"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)

    while (targets_with_snmp_result):
        target_data = targets_with_snmp_result.pop()
        scannedip = ip2long(target_data["ip"])

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for i in target_data["result"]:
            all_network_data.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "scannedip": scannedip,
                "interfaceindex": (i["Value"]).strip()
            })

    print("\t- Duration:", datetime.now() - start)
    sys.exit()

def ipaddress():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.4.20.1.2"
    oid_name = "ipaddress"
    adding_data = "oid_data"
    hostname_matched_comparing_field = "interfaceindex"
    unmatched_comparing_field = "Value"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []
    """

    print("\t- Duration:", datetime.now() - start)
    """


def status():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.2.2.1.7"
    oid_name = "status"
    adding_data = "Value"
    hostname_matched_comparing_field = "interfaceindex"
    unmatched_comparing_field = "oid_data"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []

    print("\t- Duration:", datetime.now() - start)
    """

    """


def mac_address():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.2.2.1.6"
    oid_name = "mac_address"
    adding_data = "Value"
    hostname_matched_comparing_field = "interfaceindex"
    unmatched_comparing_field = "oid_data"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []

    print("\t- Duration:", datetime.now() - start)
    """

    """


def mtu():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.2.2.1.4"
    oid_name = "mtu"
    adding_data = "Value"
    hostname_matched_comparing_field = "interfaceindex"
    unmatched_comparing_field = "oid_data"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []

    print("\t- Duration:", datetime.now() - start)
    """

    """


def netmask():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.4.20.1.3"
    oid_name = "netmask"
    adding_data = "Value"
    hostname_matched_comparing_field = "ipaddress"
    unmatched_comparing_field = "oid_data"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []

    print("\t- Duration:", datetime.now() - start)
    """

    """


def interface_type():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.2.2.1.3"
    oid_name = "interface_type"
    adding_data = "Value"
    hostname_matched_comparing_field = "interfaceindex"
    unmatched_comparing_field = "oid_data"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []

    print("\t- Duration:", datetime.now() - start)
    """
    for i in range(56):
        data = all_network_data.pop()
        print(data)

    """


def interface_description():
    global targets, targets_with_snmp_result, all_network_data, matched_temp_network_data
    start = datetime.now()
    targets_with_snmp_result = []
    snmp_oid = ".1.3.6.1.2.1.2.2.1.2"
    oid_name = "interface_description"
    adding_data = "Value"
    hostname_matched_comparing_field = "interfaceindex"
    unmatched_comparing_field = "oid_data"

    threat_snmp_and_match_data(targets, snmp_oid, oid_name)
    print(f"[*] Matching {oid_name} data.")

    while (targets_with_snmp_result):
        hostname_matched_of_all_network_data_list = []

        target_data = targets_with_snmp_result.pop()

        if not target_data["result"]:  # == "[-] Failed to get value of SNMP variable. Timeout.":
            error = f"[-] SNMP result is empty for: \n\t{target_data}"
            # print(error)
            Errors.append({
                "hostname": target_data["hostname"],
                "ip": target_data["ip"],
                "os": target_data["os"],
                "oid": snmp_oid,
                "error": error
            })
            continue
        if re.search("Failed", target_data["hostname"]) \
                or re.search("Failed",
                             str(target_data["result"])):  # == "[-] Failed to get value of SNMP variable. Timeout.":
            continue

        for index, x in enumerate(all_network_data):  # while (all_network_data):
            if x["hostname"] == target_data["hostname"]:
                hostname_matched_of_all_network_data_list.append(x)
                # all_network_data.pop(index)

        match_data(target_data["result"], unmatched_comparing_field, hostname_matched_of_all_network_data_list,
                   hostname_matched_comparing_field, oid_name, adding_data)

    all_network_data = matched_temp_network_data
    matched_temp_network_data = []

    print("\t- Duration:", datetime.now() - start)
    """

    """

def networkAdapter_data_base_insert():
    global all_network_data
    table_name = "networkAdapter"
    query = "MIB-2"
    hard_code = "Not Applicable"
    createdtime = current_time()
    value = ''
    values = ''

    for network_data in all_network_data:

        if not validate_ip(network_data["ipaddress"]): network_data["ipaddress"] = "-"
        if network_data["mac_address"] == "": network_data["mac_address"] = "-"

        if not re.match("[0-9a-f]{2}([-:\s]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", network_data["mac_address"].lower()) \
                and network_data["mac_address"] != "-" \
                and network_data["mac_address"] != "":
            h = network_data["mac_address"]
            h = h.encode("ascii").hex().upper()
            h = ' '.join(h[i:i + 2] for i in range(0, 12, 2))
            network_data["mac_address"] = h

        if network_data["status"] == "1":
            network_data["status"] = "True"
        else:
            network_data["status"] = "False"

        if network_data["interface_type"] == "53":
            physicaladapter = "False"
        elif network_data["interface_type"] == "6":
            physicaladapter = "True"
        else:
            physicaladapter = "False"

        if network_data["interface_type"] == "53":
            adapterType = "Virtual"
        elif network_data["interface_type"] == "6":
            adapterType = "Ethernet"
        else:
            adapterType = "False"

        value = query, network_data["scannedip"], network_data["os"], network_data["hostname"], scanid, createdtime, \
                network_data["interfaceindex"], hard_code, hard_code, hard_code, network_data["interface_description"], \
                network_data["interface_description"], network_data["status"], network_data[
                    "mac_address"], physicaladapter, adapterType

        value = tuple(value)
        value = str(value)
        if values:
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,interfaceindex ,netconnectionid, productname, servicename, name, description, netenabled, macaddress, physicaladapter, adapterType ) VALUES " + values + ";"
    try:
        database_handle.execute_sql(db_query)  # Insert Inventory Data To DB
        print("[+] Inserted Inventory Data of Interfaceindexes.")
    except Exception as e:
        error = f"[-] Failed To Insert Data of Interfaceindexes.\n\t[Err] {e}"
        print(error)
        Errors.append({
            "error": error
        })

def networkAdapterConfiguration_data_base_insert():
    global all_network_data
    table_name = "networkAdapterConfiguration"
    query = "MIB-2"
    hard_code = "Unknown"
    createdtime = current_time()
    value = ''
    values = ''

    for network_data in all_network_data:

        if not validate_ip(network_data["ipaddress"]): network_data["ipaddress"] = "-"
        if network_data["mac_address"] == "": network_data["mac_address"] = "-"

        # not re.match("[0-9a-f]{2}([-:\s]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", network_data["mac_address"].lower())
        if len(network_data["mac_address"]) < 12 \
                and not network_data["mac_address"].isdigit() \
                and network_data["mac_address"] != "-" \
                and network_data["mac_address"] != "":
            h = network_data["mac_address"]
            h = h.encode("ascii").hex().upper()
            h = ' '.join(h[i:i + 2] for i in range(0, 12, 2))
            network_data["mac_address"] = h

        value = query, network_data["scannedip"], network_data["os"], network_data["hostname"], scanid, createdtime, \
                network_data["interfaceindex"], hard_code, hard_code, hard_code, hard_code, hard_code, network_data[
                    "ipaddress"], network_data["interface_description"], network_data["mac_address"], network_data[
                    "mtu"], network_data["netmask"]

        value = tuple(value)
        value = str(value)
        if values:
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,interfaceindex ,dhcpserver, defaultipgateway, dnsdomain, dhcpenabled, dnshostname, ipaddress, description, macaddress, mtu, ipsubnet ) VALUES " + values + ";"
    try:
        database_handle.execute_sql(db_query)  # Insert Inventory Data To DB
        print("[+] Inserted Inventory Data of Interfaceindexes.")
    except Exception as e:
        error = f"[-] Failed To Insert Data of Interfaceindexes.\n\t[Err] {e}"
        print(error)
        Errors.append({
            "error": error
        })


def show():
    global all_network_data
    table_name = "networkAdapterConfiguration"
    query = "MIB-2"
    hard_code = "Unknown"
    createdtime = current_time()
    value = ''
    values = ''

    for network_data in all_network_data:

        if not validate_ip(network_data["ipaddress"]): network_data["ipaddress"] = "-"
        if network_data["mac_address"] == "": network_data["mac_address"] = "-"

        # not re.match("[0-9a-f]{2}([-:\s]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", network_data["mac_address"].lower())
        if len(network_data["mac_address"]) < 12 \
                and not network_data["mac_address"].isdigit() \
                and network_data["mac_address"] != "-" \
                and network_data["mac_address"] != "":
            h = network_data["mac_address"]
            h = h.encode("ascii").hex().upper()
            h = ' '.join(h[i:i + 2] for i in range(0, 12, 2))
            network_data["mac_address"] = h

    print(all_network_data)


'''

    print(unmatched_data_list)
    print(unmatched_comparing_field)
    print(hostname_matched_of_all_network_data_list)
    print(hostname_matched_comparing_field)
    print(oid_name)
    print(adding_data)

'''

get_all_credentials()

interfaceindex()
print("- Number of interfaces:", f'{len(all_network_data):,}')
status()
print("- Number of interfaces:", f'{len(all_network_data):,}')
mtu()
print("- Number of interfaces:", f'{len(all_network_data):,}')
interface_description()
print("- Number of interfaces:", f'{len(all_network_data):,}')
interface_type()
print("- Number of interfaces:", f'{len(all_network_data):,}')
mac_address()
print("- Number of interfaces:", f'{len(all_network_data):,}')
ipaddress()
print("- Number of interfaces:", f'{len(all_network_data):,}')
netmask()
print("- Number of interfaces:", f'{len(all_network_data):,}')

# print(all_network_data[0:5])

show()
print("- Number of interfaces:", f'{len(all_network_data):,}')

print("====================FINISHED====================\n")
print("Total Duration:", datetime.now() - start)

"""
if Errors : #!="":
    print("\n====================Errors====================")
    for Error in Errors :
        print(Error["error"])
    #dbquery = generate_Errors_query(Errors)
    #database_handle.execute_sql(dbquery)
    #print("Number Of Failed:", (number_of_targets - successful_inserted_count))


    for i in range(5):
        target = targets.pop()
        print ((snmp_and_match_data(target, snmp_oid)))

thread_count = 10  # int(number_of_targets / 8)
pool = ThreadPool(processes=thread_count)
for i in range(10):
    target = targets.pop()
    pool.apply_async(get_snmp_data, (target, "1.3.6.1.2.1.2.2.1.1",))
pool.close()  # Done adding tasks.
pool.join()

for i in range(10):
    target = targets.pop()
    get_snmp_data(target, "1.3.6.1.2.1.2.2.1.1")

"""