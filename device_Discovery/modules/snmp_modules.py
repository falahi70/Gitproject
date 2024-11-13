import getpass
import json
import sys
from .general_functions import *
from .database_connections import *
from .coresolution import *
import ipaddress
import subprocess
import datetime
import uuid
import psycopg2
import logging
from multiprocessing.pool import ThreadPool

config = load_config()

coresolution_handle = coresolution(
    config["coresolution_scheme"],
    config["coresolution_ipaddress"],
    config["coresolution_username"],
    config["coresolution_password"]
)
coresolution_handle.authenticate()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def current_time():
    return str(datetime.datetime.now())[:19]

def clean_command(output):
    command_result = output.decode("utf-8")
    command_result = command_result.strip()
    command_result = command_result.replace("\n", "")
    command_result = command_result.replace(r"\n", "")
    command_result = command_result.replace("\r", "")
    command_result = command_result.replace(r"\n", "")
    try:
        command_output = command_result.split(": ", 1)[-1]
    except:
        command_output = command_result
    return command_output


def walk_snmp_v3(ipaddress, credentials, start_oid, end_oid, target_details, fieldname, debug_ip):
    snmp_data = []
    username = credentials["username"]

    authentication_phrase = credentials.get("authentication_phrase", False)
    authentication_phrase = f'"{authentication_phrase}"' if authentication_phrase else ""

    authentication_type = credentials.get("authentication_type", False)
    authentication_type = f'"{authentication_type}"' if authentication_type else ""

    encryption_phrase = credentials.get("encryption_phrase", False)
    encryption_phrase = f'"{encryption_phrase}"' if encryption_phrase else ""

    encryption_type = credentials.get("encryption_type", False)
    encryption_type = f'"{encryption_type}"' if encryption_type else ""

    # if not encryption_type and not encryption_phrase:
    #     version = 2
    # else:
    #     version = 3
    version = 3
    # command = fr'SnmpWalk.exe -r:"{ipaddress}" -v:{version} -sn:"{username}" {authentication_type} {authentication_phrase} {encryption_type} {encryption_phrase} -os:"{start_oid}" -op:"{end_oid}" -q -t:10'
    command = fr'snmpwalk -v 3 -u {username} -a {authentication_type} -A {authentication_phrase} -x {encryption_type} -X {encryption_phrase} {ipaddress} {start_oid} {end_oid} -l authPriv -O n'
    if debug_ip:
        logging.info(f"[!] SNMP Command: {command}")

    process_handle = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = process_handle.communicate(timeout=10)
    except:
        output, error = b"snmpwalk: Timeout", b"snmpwalk: Timeout"

    command_result = clean_command(output)
    # print(command_result, flush=True)
    # logging.info(f"[{ipaddress}] command_result: {command_result}")
    if len(command_result) < 2:
        command_result = "snmpwalk: Timeout"

    if "snmpwalk: Timeout".lower() in command_result.lower():
        target_details["status"] = -1
        target_details["error"] = "snmpwalk: Timeout"
        target_details[fieldname] = "N/A"

    elif "Received a report pdu from remote host".lower() in command_result.lower():
        target_details["status"] = -1
        target_details["error"] = command_result
        target_details[fieldname] = "N/A"

    else:
        target_details["status"] = 1
        target_details["error"] = "N/A"
        target_details[fieldname] = command_result

    target_details["command"] = command
    target_details["command_result"] = command_result
    return target_details


def walk_snmp_v12(ipaddress, credentials, start_oid, end_oid, target_details, version, fieldname, debug_ip):
    snmp_data = []

    community = credentials.get("community", "12345")
    # command = fr'SnmpWalk.exe -v:{version} -r:"{ipaddress}" -c:"{community}" -os:"{start_oid}" -op:"{end_oid}" -q -t:10'
    command = fr'snmpwalk -v 2c -c {community} {ipaddress} {start_oid} {end_oid} -O n'
    if debug_ip:
        logging.info(f"[!] SNMP Command: {command}")
    output_handle = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = output_handle.communicate(timeout=10)
    except:
        output, error = b"snmpwalk: Timeout", b"snmpwalk: Timeout"
    command_result = clean_command(output)
    if len(command_result) < 2:
        command_result = "snmpwalk: Timeout"

    # print(f"[!] CommandResult: {command_result}")

    if "snmpwalk: Timeout".lower() in command_result.lower():
        target_details["status"] = -1
        target_details["error"] = "Failed to get value of SNMP variable. Timeout."
        target_details[fieldname] = "N/A"

    elif "Received a report pdu from remote host".lower() in command_result.lower():
        target_details["status"] = -1
        target_details["error"] = command_result
        target_details[fieldname] = "N/A"

    else:
        target_details["status"] = 1
        target_details["error"] = "N/A"
        target_details[fieldname] = command_result


    target_details["command"] = command
    target_details["command_result"] = command_result
    return target_details


def walk_snmp_v1(ipaddress, start_oid, end_oid, target_details, fieldname, debug_ip):
    snmp_data = []
    # community = credentials["community"]
    # command = fr'SnmpWalk.exe -v:{options.version} -r:"{ipaddress}" -os:"{start_oid}" -op:"{end_oid}"'
    # command = fr'SnmpWalk.exe -r:"{ipaddress}" -os:"{start_oid}" -op:"{end_oid}" -q -t:10'
    command = fr'snmpwalk -v 1 {ipaddress} {start_oid} {end_oid} -O n'
    if debug_ip:
        logging.info(f"[!] SNMP Command: {command}")

    process_handle = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = process_handle.communicate(timeout=10)
    except:
        output, error = b"snmpwalk: Timeout", b"snmpwalk: Timeout"
    command_result = clean_command(output)
    if len(command_result) < 2:
        command_result = "snmpwalk: Timeout"

    # print(f"[!] CommandResult: {command_result}")

    if "snmpwalk: Timeout".lower() in command_result.lower():
        target_details["status"] = -1
        target_details["error"] = "Failed to get value of SNMP variable. Timeout."
        target_details[fieldname] = "N/A"

    elif "Received a report pdu from remote host".lower() in command_result.lower():
        target_details["status"] = -1
        target_details["error"] = command_result
        target_details[fieldname] = "N/A"

    else:
        target_details["status"] = 1
        target_details["error"] = "N/A"
        target_details[fieldname] = command_result

    target_details["command"] = command
    target_details["command_result"] = command_result
    return target_details

def fetch_credential(credential_name, version=1):
    conn, cursor = db_connect()
    if int(version) == 3:
        syntax = f"Select username, authenticationphrase, authenticationtype, encryptionphrase, encryptiontype from asset_inventory.clixml where \"name\"='{credential_name}'"
    else:
        syntax = f"Select authenticationphrase from asset_inventory.clixml where \"name\"='{credential_name}'"
    try:
        cursor.execute(syntax)
    except Exception as e:
        print("[-] Failed To Fetch Credentials From Database.")
        print(f"\t[Err] {e}")
        sys.exit(0)
    try:
        credential_info = cursor.fetchall()[0]
    except:
        print("[-] No Credential Found With Provided Name.")
        sys.exit(0)

    try:
        credential_handle = coresolution_handle.get_credential(credential_name)
        username = credential_handle["username"]
    except Exception as e:
        username = credential_info[0]

    conn.close()
    if int(version) == 3:
        credential = {
            "username": username,
            "authentication_phrase": credential_info[1],
            "authentication_type": credential_info[2],
            "encryption_phrase": credential_info[3],
            "encryption_type": credential_info[4],
        }
    else:
        credential = {
            "community": credential_info[0]
        }
    return credential

def get_oid(input_oid):
    start_oid = input_oid
    try:
        new_oid_incrementor = int(start_oid.rsplit(".", 1)[-1]) + 1
        end_oid = f'{start_oid.rsplit(".", 1)[0]}.{new_oid_incrementor}'
    except Exception as e:
        print("[-] Invalid OID Provided.")
        return False, False
    return start_oid, end_oid

def execute_snmp_jobs(target_list, target_oid=False, output_fieldname="hostname", check_status=False, thread_count=20, debug_ip=False, connection_information={}):
    if not target_oid:
        return []

    pool = ThreadPool(processes=thread_count)
    results = []
    started = current_time()
    print(f"[SNMP] Threads jobs started. ({started})")

    while (target_list):
        target_details = target_list.pop()
        if debug_ip:
            print(f"[!] target_details: {target_details}", flush=True)
        ip_address = target_details["ipaddress_string"]
        credential_name = target_details["credential_name"]
        connection_data = connection_information[credential_name]

        version = 3 if "v3" in credential_name.lower() else 2
        start_oid, end_oid = get_oid(target_oid)


        if int(version) == 3 and int(version) != 1:
            credentials = {
                "username": connection_data.get("username", ""),
                "authentication_phrase": connection_data.get("password", ""),
                "authentication_type": connection_data.get("authtype", ""),
                "encryption_phrase": connection_data.get("privacyphrase", ""),
                "encryption_type": connection_data.get("privacytype", ""),
            }
        elif int(version) != 1:
            credentials = {
                "community": connection_data.get("password", "")
            }
        else:
            credentials = False


        if int(version) == 3:
            results.append(pool.apply_async(walk_snmp_v3,
                                            (ip_address, credentials, start_oid, end_oid, target_details,
                                             output_fieldname,debug_ip,)))
        elif int(version) == 1:
            results.append(pool.apply_async(walk_snmp_v1,
                                            (ip_address, start_oid, end_oid, target_details, output_fieldname,debug_ip,)))
        else:
            results.append(pool.apply_async(walk_snmp_v12,
                                            (ip_address, credentials, start_oid, end_oid, target_details,
                                             version, output_fieldname,debug_ip,)))
    pool.close()  # Done adding tasks.
    pool.join()  # Wait for all tasks to complete.
    results = [result.get() for result in results]
    print(f"[SNMP] Threads jobs Finished. ({current_time()})")

    return results