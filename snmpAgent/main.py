import subprocess
import argparse
import psycopg2
import sys
import datetime
import json
import getpass
from modules.databaseConnection import *
import time
from modules.coresolution import *


parser = argparse.ArgumentParser(description="SNMP Information Collector Agent")

parser.add_argument("-i", "--ipaddress",
                    default="1.1.1.1",
                    help='Your Target IP Address.')

parser.add_argument("-o", "--oid",
                    default=".1.3.6.1.2.1.4.22.1.2",
                    help='Your Desired OID To Fetch Information From.')

parser.add_argument("-c", "--credentialname",
                    default=False,
                    help='Credential Name For Your Target IP Address.')

parser.add_argument("-v", "--version",
                    default=3,
                    help='SNMP Version To Connect With.')

parser.add_argument("-d", "--debug",
                    default=False,
                    action="store_true",
                    help='Print verbose messages for debugging.')

parser.add_argument("-tn", "--tablename",
                    default=False,
                    help='Enter your table name.')

parser.add_argument("-sn", "--schemaname",
                    default=False,
                    help='Enter your schema name.')

parser.add_argument("-p", "--profile",
                    default=False,
                    help='Use a profile in order to regenerate JSON output based on that.')

parser.add_argument("-ho", "--hostname",
                    default=False,
                    help='Enter target hostname for inventory.')

parser.add_argument("-st", "--store",
                    default=False,
                    action="store_true",
                    help='Store data into database instead of STDOUT.')

parser.add_argument("-x", "--batch",
                    default=False,
                    help='Pass multiple ip/credential pairs with @@ seperator.')

options = parser.parse_args()

# if not options.version and not options.batch:
#     print("Please Specify Version In The Request.")
#     sys.exit(0)



# config_path = rf"C:\Users\SVC-CoreInspect\snmpAgent"
current_user = str(getpass.getuser()).split("\\")[-1]
config_path = rf"/CoreInspect/agents/snmpAgent"
try:
    config = open(rf"{config_path}/appsettings.json", "r", encoding="utf-8", errors="ignore")
    config = json.load(config)
except Exception as e:
    print("[-] Could Not Find Config File On System.")
    print(f"\t[Err] Expected Location: {config_path}")
    sys.exit(0)

# try:
#     if int(options.version) not in [1,2,3] and not options.batch:
#         print("[-] Please Enter A Valid SNMP Version.")
#         sys.exit(0)
# except Exception as e:
#     print("[-] Please Enter A Valid SNMP Version.")
#     sys.exit(0)

if not options.ipaddress and not options.batch:
    print("[-] Please Enter A Valid IP Address.")
    sys.exit(0)

if not options.oid:
    print("[-] Please Specify An OID To Fetch Information From.")
    sys.exit(0)
elif "." not in options.oid:
    print("[-] Please Enter A Valid OID.")
    sys.exit(0)

def verbose_print(message):
    if options.debug:
        print(message)

def profile_handler(command_output, profile):
    profile_output = []
    for output in command_output:
        new_profile = profile
        for key, value in profile.items():
            value = str(value)
            if len(value.split(" | ")) > 1:  # $dhcpenabled$ | Disabled,False;Enabled,True
                value_data = value.split(" | ")[0]  # $dhcpenabled$
                value_split = value.split(" | ")[-1]  # Disabled,False;Enabled,True
            else:
                value_data = value  # $dhcpenabled$
                value_split = False
            if str(value_data).count("$") == 2:
                join_key = value_data.replace("$", "")  # dhcpenabled
                data = output[join_key]  # dhcpenabled --> Disabled
                if value_split:  # Disabled,False;Enabled,True
                    replace_list = value_split.split(";")  # ["Disabled,False","Enabled,True"]
                    for replace_action in replace_list:  # Disabled,False
                        original, new_data = replace_action.split(",")  # Original: Disabled, new_data: False
                        data = data.replace(original, new_data)
                try:
                    new_profile[key] = data
                except:
                    new_profile[key] = "unknown"
            else:
                new_profile[key] = value
        profile_output.append(new_profile)

    return profile_output

def get_oid():
    start_oid = options.oid
    verbose_print(f"[+] Start OID: {start_oid}")
    try:
        new_oid_incrementor = int(start_oid.rsplit(".", 1)[-1]) + 1
        end_oid = f'{start_oid.rsplit(".", 1)[0]}.{new_oid_incrementor}'
    except Exception as e:
        print("[-] Invalid OID Provided.")
        sys.exit(0)
    verbose_print(f"[+] End OID: {end_oid}")
    return start_oid, end_oid

def create_connection():
    try:
        conn = psycopg2.connect(
            host=config["databaseHost"],
            database=config["databaseName"],
            user=config["databaseUsername"],
            password=config["databasePassword"])

        ps_cursor = conn.cursor()
    except Exception as e:
        print("[-] Failed To Connect To Database.")
        print(f"\t[Err] {e}")
        sys.exit(0)

    return conn, ps_cursor

def fetch_credential(credential_name):
    credential = coresolution_handle.get_snmp_credential(credential_name)
    return credential

def return_json_line(line):
    data_dict = {}
    # .1.3.6.1.2.1.4.22.1.2.20.192.168.20.8 = STRING: 18:68:cb:7:2c:b6
    try:
        oid_value, type_and_value = line.split(" = ")
        value_type, data = type_and_value.split(": ")
    except:
        return {}

    oid_data = oid_value.rsplit(".", 4)
    oid_data = f"{oid_data[-4]}.{oid_data[-3]}.{oid_data[-2]}.{oid_data[-1]}"
    data_dict["oid_data"] = oid_data
    data_dict["OID"] = oid_value
    data_dict["Type"] = value_type
    data_dict["Value"] = data

    return data_dict.copy()


    # try:
    #     for data in line:
    #         key_value = data.split("=")
    #         key = key_value[0]
    #         value = key_value[1]
    #         while value[0] == " ":
    #             value = value[1:]
    #         data_dict[key] = value
    #         if key == "OID":
    #             oid_data = value.rsplit(".", 4)
    #             oid_data = f"{oid_data[-4]}.{oid_data[-3]}.{oid_data[-2]}.{oid_data[-1]}"
    #             data_dict["oid_data"] = oid_data
    #
    # except Exception as e:
    #     return {}
    # return data_dict

def sanitize_json(data):
    data = str(data)
    data = data.replace('"', r'\"')
    data = data.replace("'", '"')
    data = data.replace(": False", ': false')
    data = data.replace(": True", ': true')
    return data

def walk_snmp_v3(ipaddress, credentials, start_oid, end_oid):
    snmp_data = []
    username = credentials["username"]
    authentication_phrase = credentials["authentication_phrase"]
    authentication_type = credentials["authentication_type"]
    if  "SHA" in authentication_type:
        authentication_type = "SHA"
    encryption_phrase = credentials["encryption_phrase"]
    encryption_type = f'{credentials["encryption_type"]}' if credentials["encryption_type"] != "-" else ""
    if "AES" in  encryption_type:
        encryption_type = "AES"
    # command = fr'SnmpWalk.exe -r:"{ipaddress}" -v:3 -sn:"{username}" -ap:"{authentication_type}" -aw:"{authentication_phrase}" {encryption_type} -pw:"{encryption_phrase}" -os:"{start_oid}" -op:"{end_oid}"'
    command = fr'snmpwalk -v 3 -u {username} -a {authentication_type} -A {authentication_phrase} -x {encryption_type} -X {encryption_phrase} {ipaddress} {start_oid} {end_oid} -l authPriv -O n'
    verbose_print(f"[+] Executing SNMP Walk Command:\n\t[CMD] {command}")
    # print(f"[!] command: {command}")
    output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    verbose_print(f'[+] Command Output: {output.stdout.decode("utf-8")}')
    for line in output.stdout.splitlines():
        line = line.decode("utf-8")
        line = line.strip()
        if "snmpwalk: Timeout" in line:
            return ["Failed to get value of SNMP variable. Timeout."]
        if "= " not in line and ": " not in line:
            continue
        data = return_json_line(line)
        if len(data) > 0:
            snmp_data.append(data)
    return snmp_data

def walk_snmp_v12(ipaddress, credentials, start_oid, end_oid):
    snmp_data = []
    try:
        community = credentials["community"]
    except Exception as e:
        community = False
    # print(f"[!] credentials: {credentials}")
    # print(f"[!] Community: {community}")
    if community:
        # command = fr'SnmpWalk.exe -v:2 -r:"{ipaddress}" -c:"{community}" -os:"{start_oid}" -op:"{end_oid}"'
        command = fr'snmpwalk -v 2c -c {community} {ipaddress} {start_oid} {end_oid} -O n'
    else:
        command = fr'snmpwalk -v 2c {ipaddress} {start_oid} {end_oid} -O n'

    # print(f"[!] command: {command}")

    verbose_print(f"[+] Executing SNMP Walk Command:\n\t[CMD] {command}")
    # print(command)
    output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    verbose_print(f'[+] Command Output: {output.stdout.decode("utf-8")}')
    for line in output.stdout.splitlines():
        line = line.decode("utf-8")
        line = line.strip()
        if "Failed to get value of SNMP variable. Timeout." in line:
            return ["[-] Failed to get value of SNMP variable. Timeout."]
        if "," not in line and "=" not in line:
            continue
        data = return_json_line(line)
        if len(data) > 0:
            snmp_data.append(data)
    return snmp_data

def walk_snmp_v1(ipaddress, start_oid, end_oid):
    snmp_data = []
    # community = credentials["community"]
    # command = fr'SnmpWalk.exe -v:{options.version} -r:"{ipaddress}" -os:"{start_oid}" -op:"{end_oid}"'
    # command = fr'SnmpWalk.exe -r:"{ipaddress}" -os:"{start_oid}" -op:"{end_oid}"'
    command = fr'snmpwalk -v 1 {ipaddress} {start_oid} {end_oid} -O n'
    # print(f"[!] command: {command}")
    verbose_print(f"[+] Executing SNMP Walk Command:\n\t[CMD] {command}")
    # print(command)
    output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    for line in output.stdout.splitlines():
        line = line.decode("utf-8")
        line = line.strip()
        if "Failed to get value of SNMP variable. Timeout." in line:
            return ["[-] Failed to get value of SNMP variable. Timeout."]
        if "," not in line and "=" not in line:
            continue
        data = return_json_line(line)
        if len(data) > 0:
            snmp_data.append(data)
    return snmp_data

coresolution_handle = coresolution(
    config["coresolution_scheme"],
    config["coresolution_ipaddress"],
    config["coresolution_username"],
    config["coresolution_password"],
)
coresolution_handle.authenticate()

if options.batch:
    final_results_list = []
    full_data_tuple = options.batch.split(",")
    for data_tuple in full_data_tuple:
        final_results_json = {}
        resource_key, ip_address, credential_profile, credential_name, version = data_tuple.split("@@")
        final_results_json["resourceKey"] = resource_key
        final_results_json["credentialProfile"] = credential_profile
        final_results_json["credentialName"] = credential_name
        final_results_json["version"] = version
        if int(final_results_json["version"]) in [1, 2]:
            community = coresolution_handle.get_credential(final_results_json["credentialName"])["password"]
            final_results_json["community"] = community
        final_results_json["ipAddress"] = ip_address
        final_results_json["targetOID"] = options.oid
        # print(f"[+] Version: {version}")

        if int(version) != 1:
            credentials = fetch_credential(credential_name)

        start_oid, end_oid = get_oid()
        if int(version) == 3:
            snmp_data = walk_snmp_v3(ip_address, credentials, start_oid, end_oid)
        elif int(version) == 1:
            snmp_data = walk_snmp_v1(ip_address, start_oid, end_oid)
        else:
            snmp_data = walk_snmp_v12(ip_address, credentials, start_oid, end_oid)

        final_results_json["result"] = snmp_data
        try:
            del final_results_json["community"]
        except Exception as e:
            pass
        final_results_list.append(final_results_json)
        # snmp_data = json.dumps(snmp_data)
        # snmp_data = sanitize_json(snmp_data)
    print_data = json.dumps(final_results_list)
    print(print_data)
    sys.exit(0)




credentials = fetch_credential(options.credentialname)
snmp_version = credentials["version"]

start_oid, end_oid = get_oid()
if int(snmp_version) == 3:
    snmp_data = walk_snmp_v3(options.ipaddress, credentials, start_oid, end_oid)
elif int(snmp_version) == 1:
    snmp_data = walk_snmp_v1(options.ipaddress, start_oid, end_oid)
else:
    snmp_data = walk_snmp_v12(options.ipaddress, credentials, start_oid, end_oid)

if not options.store:
    snmp_data = json.dumps(snmp_data)
    # snmp_data = sanitize_json(snmp_data)
    print(snmp_data)

else:
    try:
        profile = json.load(open(rf"profiles/{options.profile}", "r", encoding="utf-8", errors="ignore"))
    except Exception as e:
        print(f"[-] Error while trying to read profile.\n\t[Err] {e}")
        sys.exit(0)

    parsed_snmp_data = profile_handler(snmp_data, profile)

    if len(parsed_snmp_data) < 1:
        print('[-] No Data Returned From SNMP.')
        sys.exit(0)

    current_schema_name = options.schemaname.lower()
    schema_list = get_schema_list()
    if current_schema_name not in schema_list:
        verbose_print(f"[DBUG] Schema Does Not Exist. Creating [{current_schema_name}]")
        create_new_schema(current_schema_name)

    current_table_name = options.tablename
    tablename_list = get_tablename_list(current_schema_name)
    if current_table_name not in tablename_list:
        verbose_print(f"[DBUG] Table Does Not Exist. Creating [{current_table_name}]")
        create_new_table(current_schema_name, current_table_name)

    current_column_list = parsed_snmp_data[0].keys()
    column_list = get_columnname_list(current_schema_name, current_table_name)
    for column in current_column_list:
        if column not in column_list:
            verbose_print(f"[DBUG] Column Does Not Exist. Creating [{column}]")
            create_new_column(current_schema_name, current_table_name, column)
    # scanid = get_scan_id(current_schema_name, current_table_name, options.hostname)
    for data in parsed_snmp_data:
        verbose_print("[*] Saving data into database...")
        # data["scanid"] = scanid
        insert_dictionary_data(current_schema_name, current_table_name, data)
