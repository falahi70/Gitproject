import psycopg2
import json
from psycopg2 import Error
import datetime
import base64
import sys
import argparse
import json
import time
from modules.general_functions import *
from modules.database_connections import *

# First import "from" and then other imports

parser = argparse.ArgumentParser(description="ChangeManagement: WMI Inventory Change Management.")

parser.add_argument("-d", "--debug",
                    default=False,
                    action="store_true",
                    help='Show verbose debug messages.')

parser.add_argument("-o", "--os-type",
                    default=False,
                    help='Start change management for a specific OS family.')

options = parser.parse_args()


def debug_print(message):
    if options.debug:
        print(message)

#================================================================================================================================
"""
Steps:
1- per each hostname get final scan-id for desired table
2- per each hostname gather the scan digest, record-id and identifier for final and older scan-ids
3- compare between scan-ids with following actions:
	- if in final but not in older >> added item
	- if in older but not in final >> deleted item
    - for duplicated items:
        - if same scandigest, ignore
        - if different scandigests >> modified item
4- insert data to table accordingly
5- execute change management procedures
"""
#================================================================================================================================
configurations = load_config()

# Constants

USER = configurations["database_connection"]["username"]
PASSWORD = configurations["database_connection"]["password"]
HOST = configurations["database_connection"]["hostname"]
PORT = configurations["database_connection"]["port"]
DATABASE = configurations["database_connection"]["db_name"]
database_handle = databaseConnection(
    HOST,
    USER,
    PASSWORD,
    DATABASE
)

IDENTIFIER_BIOS = configurations["IDENTIFIER_BIOS"]
IDENTIFIER_SYSTEM_DRIVER = configurations["IDENTIFIER_SYSTEM_DRIVER"]
IDENTIFIER_BOOT_CONFIGURATION = configurations["IDENTIFIER_BOOT_CONFIGURATION"]
IDENTIFIER_CDROM_DRIVE = configurations["IDENTIFIER_CDROM_DRIVE"]
IDENTIFIER_COMPUTER_SYSTEM = configurations["IDENTIFIER_COMPUTER_SYSTEM"]
IDENTIFIER_DISK_DRIVE = configurations["IDENTIFIER_DISK_DRIVE"]
IDENTIFIER_GROUP = configurations["IDENTIFIER_GROUP"]
IDENTIFIER_GROUP_USER = configurations["IDENTIFIER_GROUP_USER"]
IDENTIFIER_LOGICAL_DISK = configurations["IDENTIFIER_LOGICAL_DISK"]
IDENTIFIER_NETWORK_ADAPTER_CONFIGURATION = configurations["IDENTIFIER_NETWORK_ADAPTER_CONFIGURATION"]
IDENTIFIER_OPERATING_SYSTEM = configurations["IDENTIFIER_OPERATING_SYSTEM"]
IDENTIFIER_PHYSICAL_MEMORY = configurations["IDENTIFIER_PHYSICAL_MEMORY"]
IDENTIFIER_PRINTER = configurations["IDENTIFIER_PRINTER"]
IDENTIFIER_PRINTER_CONFIGURATION = configurations["IDENTIFIER_PRINTER_CONFIGURATION"]
IDENTIFIER_PROCESSOR = configurations["IDENTIFIER_PROCESSOR"]
IDENTIFIER_PRODUCT = configurations["IDENTIFIER_PRODUCT"]
IDENTIFIER_QUICK_FIX_ENGINEERING = configurations["IDENTIFIER_QUICK_FIX_ENGINEERING"]
IDENTIFIER_SERVICE = configurations["IDENTIFIER_SERVICE"]
IDENTIFIER_STARTUP_COMMAND = configurations["IDENTIFIER_STARTUP_COMMAND"]
IDENTIFIER_USB_CONTROLLER = configurations["IDENTIFIER_USB_CONTROLLER"]
IDENTIFIER_USER_ACCOUNT = configurations["IDENTIFIER_USER_ACCOUNT"]

# Move all constanst to appsettings.json

MODIFIER_LIST_BIOS = configurations["modifier_lists"]["MODIFIER_LIST_BIOS"]
MODIFIER_LIST_SYSTEM_DRIVER = configurations["modifier_lists"]["MODIFIER_LIST_SYSTEM_DRIVER"]
MODIFIER_LIST_BOOT_CONFIGURATION = configurations["modifier_lists"]["MODIFIER_LIST_BOOT_CONFIGURATION"]
MODIFIER_LIST_DISK_DRIVE = configurations["modifier_lists"]["MODIFIER_LIST_DISK_DRIVE"]
MODIFIER_LIST_GROUP = configurations["modifier_lists"]["MODIFIER_LIST_GROUP"]
MODIFIER_LIST_GROUP_USER = configurations["modifier_lists"]["MODIFIER_LIST_GROUP_USER"]
MODIFIER_LIST_LOGICAL_DISK = configurations["modifier_lists"]["MODIFIER_LIST_LOGICAL_DISK"]
MODIFIER_LIST_NETWORK_ADAPTER_CONFIGURATION = configurations["modifier_lists"]["MODIFIER_LIST_NETWORK_ADAPTER_CONFIGURATION"]
MODIFIER_LIST_OPERATING_SYSTEM = configurations["modifier_lists"]["MODIFIER_LIST_OPERATING_SYSTEM"]
MODIFIER_LIST_PHYSICAL_MEMORY = configurations["modifier_lists"]["MODIFIER_LIST_PHYSICAL_MEMORY"]
MODIFIER_LIST_PROCESSOR = configurations["modifier_lists"]["MODIFIER_LIST_PROCESSOR"]
MODIFIER_LIST_PRODUCT = configurations["modifier_lists"]["MODIFIER_LIST_PRODUCT"]
MODIFIER_LIST_QUICK_FIX_ENGINEERING = configurations["modifier_lists"]["MODIFIER_LIST_QUICK_FIX_ENGINEERING"]
MODIFIER_LIST_STARTUP_COMMAND = configurations["modifier_lists"]["MODIFIER_LIST_STARTUP_COMMAND"]
MODIFIER_LIST_USB_CONTROLLER = configurations["modifier_lists"]["MODIFIER_LIST_USB_CONTROLLER"]
MODIFIER_LIST_USER_ACCOUNT = configurations["modifier_lists"]["MODIFIER_LIST_USER_ACCOUNT"]
MODIFIER_LIST_CDROM_DRIVE = configurations["modifier_lists"]["MODIFIER_LIST_CDROM_DRIVE"]
MODIFIER_LIST_COMPUTER_SYSTEM = configurations["modifier_lists"]["MODIFIER_LIST_COMPUTER_SYSTEM"]
MODIFIER_LIST_SERVICE = configurations["modifier_lists"]["MODIFIER_LIST_SERVICE"]


MODULE_BIOS = configurations["module_names"]["MODULE_BIOS"]
MODULE_SYSTEM_DRIVER = configurations["module_names"]["MODULE_SYSTEM_DRIVER"]
MODULE_BOOT_CONFIGURATION = configurations["module_names"]["MODULE_BOOT_CONFIGURATION"]
MODULE_CDROM_DRIVE = configurations["module_names"]["MODULE_CDROM_DRIVE"]
MODULE_COMPUTER_SYSTEM = configurations["module_names"]["MODULE_COMPUTER_SYSTEM"]
MODULE_DISK_DRIVE = configurations["module_names"]["MODULE_DISK_DRIVE"]
MODULE_GROUP = configurations["module_names"]["MODULE_GROUP"]
MODULE_GROUP_USER = configurations["module_names"]["MODULE_GROUP_USER"]
MODULE_LOGICAL_DISK = configurations["module_names"]["MODULE_LOGICAL_DISK"]
MODULE_NETWORK_ADAPTER_CONFIGURATION = configurations["module_names"]["MODULE_NETWORK_ADAPTER_CONFIGURATION"]
MODULE_OPERATING_SYSTEM = configurations["module_names"]["MODULE_OPERATING_SYSTEM"]
MODULE_PHYSICAL_MEMORY = configurations["module_names"]["MODULE_PHYSICAL_MEMORY"]
MODULE_PRINTER = configurations["module_names"]["MODULE_PRINTER"]
MODULE_PRINTER_CONFIGURATION = configurations["module_names"]["MODULE_PRINTER_CONFIGURATION"]
MODULE_PROCESSOR = configurations["module_names"]["MODULE_PROCESSOR"]
MODULE_PRODUCT = configurations["module_names"]["MODULE_PRODUCT"]
MODULE_QUICK_FIX_ENGINEERING = configurations["module_names"]["MODULE_QUICK_FIX_ENGINEERING"]
MODULE_SERVICE = configurations["module_names"]["MODULE_SERVICE"]
MODULE_STARTUP_COMMAND = configurations["module_names"]["MODULE_STARTUP_COMMAND"]
MODULE_USB_CONTROLLER = configurations["module_names"]["MODULE_USB_CONTROLLER"]
MODULE_USER_ACCOUNT = configurations["module_names"]["MODULE_USER_ACCOUNT"]

#================================================================================================================================
#Step 1: per each hostname get final scan-id for desired table
#Step Input: Database credentials
#Step Output: a list of dictionaries with hostname as key and final scan-id as value

def db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, QUERY):
    try:
        connection = psycopg2.connect(user = USER,
                                      password = PASSWORD,
                                      host = HOST,
                                      port = PORT,
                                      database = DATABASE)
    except (Exception, Error) as error:
        print("Error while connecting to PostgreSQL", error)
        sys.exit(0)
    finally:
        #print("PostgreSQL connection is established." + "\t", datetime.datetime.now())
        cursor = connection.cursor()
        debug_print(f"[+] Query: {QUERY}")
        cursor.execute(QUERY)
        query_result = cursor.fetchall()
        cursor.close()
        connection.close()
        #print("PostgreSQL connection is closed." + "\t", datetime.datetime.now())
    return query_result

def db_insert_query(USER, PASSWORD, HOST, PORT, DATABASE, QUERY):
    try:
        connection = psycopg2.connect(user = USER,
                                      password = PASSWORD,
                                      host = HOST,
                                      port = PORT,
                                      database = DATABASE)
    except (Exception, Error) as error:
        print("Error while connecting to PostgreSQL", error)
        sys.exit(0)
    finally:
        #print("PostgreSQL connection is established." + "\t", datetime.datetime.now())
        cursor = connection.cursor()
        cursor.execute(QUERY)
        connection.commit()
        cursor.close()
        connection.close()
        #print("PostgreSQL connection is closed." + "\t", datetime.datetime.now())
    return "Done"

def parse_hostname_and_scan_id(query_result, table):
    scan_id_per_hostname = {}
    scan_id_per_hostname_list = []
    for i in range (0, len(query_result)):
        host = ''.join(query_result[i][0])
        scan_id = ''.join(str(query_result[i][1]))
        scan_id_per_hostname["hostname"] = host
        scan_id_per_hostname["scanid"] = int(scan_id)
        scan_id_per_hostname["table"] = table
        scan_id_per_hostname_list.append(scan_id_per_hostname.copy())
    #scan_id_per_hostname = json.dumps(scan_id_per_hostname)
    return scan_id_per_hostname_list
    
def get_hostname_and_scan_id(table):
    table = table.lower()
    if options.os_type:
        hostname_and_id_query = f"SELECT hostname, \"{table}\" FROM inventory_history.asset_inventory_scan_history WHERE \"{table}\" >= '2' and osfamily LIKE '{options.os_type}';"
    else:
        hostname_and_id_query = f"SELECT hostname, \"{table}\" FROM inventory_history.asset_inventory_scan_history WHERE \"{table}\" >= '2';"
    debug_print(hostname_and_id_query)
    hostname_and_id = db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, hostname_and_id_query)
    parsed_hostname_and_id = parse_hostname_and_scan_id(hostname_and_id, table)

    # [{'hostname': 'Saee.SB24.ir', 'scanid': 5, 'table': 'networkadapterconfiguration'}]
    return parsed_hostname_and_id


def scan_order_calculator(column_list, column_values, tablename, hostname, scanid, scanid2):
    # print(f"column_list:\n{column_list}")
    # print(f"column_values:\n{column_values}")
    # print(f"tablename:\n{tablename}")
    # print(f"hostname:\n{hostname}")
    # print(f"scanid:\n{scanid}")
    # print(f"scanid2:\n{scanid2}")
    query_conditions = ""
    for counter in range(0,len(column_list)):
        column_value = column_values[counter]
        if "str" in str(type(column_value)):
            column_value = column_value.replace("'", r"''")
            query_conditions = query_conditions + f'and {column_list[counter]}=\'{column_value}\' '
        elif "None" in str(type(column_value)):
            query_conditions = query_conditions + f'and {column_list[counter]}=Null '
        else:
            column_value = column_value.replace("'", r"''")
            query_conditions = query_conditions + f'and {column_list[counter]}=\'{column_value}\' '
    # print(query_conditions)
    query_conditions = query_conditions[4:]
    first_query = f'select id, scanid from asset_inventory."{tablename}" where {query_conditions} and scanid={scanid} and hostname=\'{hostname}\''
    first_query = first_query.replace("=Null", " is null")

    second_query = f'select id, scanid from asset_inventory."{tablename}" where {query_conditions} and scanid={scanid2} and hostname=\'{hostname}\''
    second_query = second_query.replace("=Null", " is null")

    # print(f"first_query:\n{first_query}")
    # print(f"second_query:\n{second_query}")

    first_result = db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, first_query)
    second_result = db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, second_query)

    #
    # print(f"first_result:\n{first_result}")
    # print(f"second_result:\n{second_result}")


    #print(f'Result-1 {first_result}')
    #print(f'Result-2 {second_result}')
    if len(first_result) > 0:
        print(first_result[0][0], first_result[0][1], scanid)
        return first_result[0][0], first_result[0][1], scanid
    elif len(second_result) > 0:
        print(second_result[0][0], second_result[0][1], scanid2)
        return second_result[0][0], second_result[0][1], scanid2
    else:
        print(second_result[0][0], second_result[0][1], scanid2)
        return second_result[0][0], second_result[0][1], scanid2


#print(parsed_hostname_and_id)
#================================================================================================================================
#Step 2: per each hostname gather the scan digest, record-id and identifier for final and older scan-ids
#Step Input: hostname to final scan-id dictionary 
#Step Output: a list of dictionaries with all the required fields, for both final and older scan-ids

def get_scan_digest_for_scan_id(target_info, scanid):
    hostname = target_info["hostname"]
    # if decrease_scanid:
    #     scanid = int(database_handle.get_older_scanid("asset_inventory", target_info["target_table"],
    #                                                   int(target_info["scanid"]), hostname))
    # else:
    #     scanid = int(target_info["scanid"])

    table = target_info["target_table"]

    if table == "bios":
        objectidentifier = IDENTIFIER_BIOS
        module = MODULE_BIOS
        modifier_list = MODIFIER_LIST_BIOS
    elif table == "systemDriver":
        objectidentifier = IDENTIFIER_SYSTEM_DRIVER
        module = MODULE_SYSTEM_DRIVER
        modifier_list = MODIFIER_LIST_SYSTEM_DRIVER
    elif table == "bootConfiguration":
        objectidentifier = IDENTIFIER_BOOT_CONFIGURATION
        module = MODULE_BOOT_CONFIGURATION
        modifier_list = MODIFIER_LIST_BOOT_CONFIGURATION
    elif table == "cdromDrive":
        objectidentifier = IDENTIFIER_CDROM_DRIVE
        module = MODULE_CDROM_DRIVE
        modifier_list = MODIFIER_LIST_CDROM_DRIVE
    elif table == "group":
        objectidentifier = IDENTIFIER_GROUP
        module = MODULE_GROUP
        modifier_list = MODIFIER_LIST_GROUP
    elif table == "diskDrive":
        objectidentifier = IDENTIFIER_DISK_DRIVE
        module = MODULE_DISK_DRIVE
        modifier_list = MODIFIER_LIST_DISK_DRIVE
    elif table == "computerSystem":
        objectidentifier = IDENTIFIER_COMPUTER_SYSTEM
        module = MODULE_COMPUTER_SYSTEM
        modifier_list = MODIFIER_LIST_COMPUTER_SYSTEM
    elif table == "groupUser":
        objectidentifier = IDENTIFIER_GROUP_USER
        module = MODULE_GROUP_USER
        modifier_list = MODIFIER_LIST_GROUP_USER
    elif table == "logicalDisk":
        objectidentifier = IDENTIFIER_LOGICAL_DISK
        module = MODULE_LOGICAL_DISK
        modifier_list = MODIFIER_LIST_LOGICAL_DISK
    elif table == "networkAdapterConfiguration":
        objectidentifier = IDENTIFIER_NETWORK_ADAPTER_CONFIGURATION
        module = MODULE_NETWORK_ADAPTER_CONFIGURATION
        modifier_list = MODIFIER_LIST_NETWORK_ADAPTER_CONFIGURATION
    elif table == "operatingSystem":
        objectidentifier = IDENTIFIER_OPERATING_SYSTEM
        module = MODULE_OPERATING_SYSTEM
        modifier_list = MODIFIER_LIST_OPERATING_SYSTEM
    elif table == "physicalMemory":
        objectidentifier = IDENTIFIER_PHYSICAL_MEMORY
        module = MODULE_PHYSICAL_MEMORY
        modifier_list = MODIFIER_LIST_PHYSICAL_MEMORY
    elif table == "printer":
        objectidentifier = IDENTIFIER_PRINTER
        module = MODULE_PRINTER
        modifier_list = []
    elif table == "printerConfiguration":
        objectidentifier = IDENTIFIER_PRINTER_CONFIGURATION
        module = MODULE_PRINTER_CONFIGURATION
        modifier_list = []
    elif table == "processor":
        objectidentifier = IDENTIFIER_PROCESSOR
        module = MODULE_PROCESSOR
        modifier_list = MODIFIER_LIST_PROCESSOR
    elif table == "product":
        objectidentifier = IDENTIFIER_PRODUCT
        module = MODULE_PRODUCT
        modifier_list = MODIFIER_LIST_PRODUCT
    elif table == "quickFixEngineering":
        objectidentifier = IDENTIFIER_QUICK_FIX_ENGINEERING
        module = MODULE_QUICK_FIX_ENGINEERING
        modifier_list = MODIFIER_LIST_QUICK_FIX_ENGINEERING
    elif table == "service":
        objectidentifier = IDENTIFIER_SERVICE
        module = MODULE_SERVICE
        modifier_list = MODIFIER_LIST_SERVICE
    elif table == "startupCommand":
        objectidentifier = IDENTIFIER_STARTUP_COMMAND
        module = MODULE_STARTUP_COMMAND
        modifier_list = MODIFIER_LIST_STARTUP_COMMAND
    elif table == "usbController":
        objectidentifier = IDENTIFIER_USB_CONTROLLER
        module = MODULE_USB_CONTROLLER
        modifier_list = MODIFIER_LIST_USB_CONTROLLER
    elif table == "userAccount":
        objectidentifier = IDENTIFIER_USER_ACCOUNT
        module = MODULE_USER_ACCOUNT
        modifier_list = MODIFIER_LIST_USER_ACCOUNT
    else:
        debug_print(f"table [{table}] not found.")
        return False

    col_list = modifier_list
    try:
        col_list.remove(objectidentifier)
    except:
        pass
    col_list.append(objectidentifier)
    col_list = tuple(col_list)
    column_list = ",".join(col_list)
    column_list = f"id,{column_list}"
    column_list_splited = column_list.split(",")
    get_scan_digest = f"SELECT {column_list} FROM asset_inventory.\"{table}\" WHERE hostname = '{hostname}' AND scanid = {scanid}"
    # print(f"[!] get_scan_digest: {get_scan_digest}")
    # Sample Query: SELECT id, defaultipgateway,dhcpenabled,dhcpserver,dnsdomain,ipaddress,ipsubnet,interfaceindex,macaddress FROM asset_inventory."networkAdapterConfiguration" WHERE hostname = '9304-7PC71' AND scanid = 9
    #  Sample Returned Data: ('1025513', 'None', 'False', 'None', 'None', 'None', 'None', '2', 'None')
    scan_digest_list = db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, get_scan_digest)
    parsed_scan_digest_result = []
    for result in scan_digest_list:
        tmp_data = {}
        for num in range(0, len(column_list.split(","))):
            tmp_data[column_list_splited[num]] = result[num]
        parsed_scan_digest_result.append(tmp_data.copy())

    target_info[scanid] = parsed_scan_digest_result
    return target_info.copy()


#scan_digest_final = get_scan_digest_for_scan_id("A-FATHI", 3, "service")
#print(scan_digest_final)    

def generate_dictionary_for_scan_digest(target_info, latest_scanid):
    table = target_info["target_table"]

    scan_digest_dictionary = target_info.copy()
    if table == "bios":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_BIOS
        scan_digest_dictionary["module"] = MODULE_BIOS
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_BIOS
    elif table == "systemDriver":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_SYSTEM_DRIVER
        scan_digest_dictionary["module"] = MODULE_SYSTEM_DRIVER
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_SYSTEM_DRIVER
    elif table == "bootConfiguration":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_BOOT_CONFIGURATION
        scan_digest_dictionary["module"] = MODULE_BOOT_CONFIGURATION  
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_BOOT_CONFIGURATION        
    elif table == "cdromDrive":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_CDROM_DRIVE
        scan_digest_dictionary["module"] = MODULE_CDROM_DRIVE
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_CDROM_DRIVE
    elif table == "group":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_GROUP
        scan_digest_dictionary["module"] = MODULE_GROUP
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_GROUP
    elif table == "diskDrive":
        scan_digest_dictionary["objectidentifier"]  = IDENTIFIER_DISK_DRIVE
        scan_digest_dictionary["module"] = MODULE_DISK_DRIVE
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_DISK_DRIVE
    elif table == "computerSystem":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_COMPUTER_SYSTEM   
        scan_digest_dictionary["module"] = MODULE_COMPUTER_SYSTEM
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_COMPUTER_SYSTEM
    elif table == "groupUser":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_GROUP_USER
        scan_digest_dictionary["module"] = MODULE_GROUP_USER
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_GROUP_USER
    elif table == "logicalDisk":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_LOGICAL_DISK
        scan_digest_dictionary["module"] = MODULE_LOGICAL_DISK
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_LOGICAL_DISK
    elif table == "networkAdapterConfiguration":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_NETWORK_ADAPTER_CONFIGURATION
        scan_digest_dictionary["module"] = MODULE_NETWORK_ADAPTER_CONFIGURATION
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_NETWORK_ADAPTER_CONFIGURATION
    elif table == "operatingSystem":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_OPERATING_SYSTEM
        scan_digest_dictionary["module"] = MODULE_OPERATING_SYSTEM
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_OPERATING_SYSTEM
    elif table == "physicalMemory":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_PHYSICAL_MEMORY
        scan_digest_dictionary["module"] = MODULE_PHYSICAL_MEMORY
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_PHYSICAL_MEMORY
    elif table == "printer":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_PRINTER
        scan_digest_dictionary["module"] = MODULE_PRINTER
    elif table == "printerConfiguration":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_PRINTER_CONFIGURATION
        scan_digest_dictionary["module"] = MODULE_PRINTER_CONFIGURATION
    elif table == "processor":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_PROCESSOR
        scan_digest_dictionary["module"] = MODULE_PROCESSOR
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_PROCESSOR
    elif table == "product":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_PRODUCT
        scan_digest_dictionary["module"] = MODULE_PRODUCT
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_PRODUCT
    elif table == "quickFixEngineering":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_QUICK_FIX_ENGINEERING
        scan_digest_dictionary["module"] = MODULE_QUICK_FIX_ENGINEERING
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_QUICK_FIX_ENGINEERING
    elif table == "service":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_SERVICE
        scan_digest_dictionary["module"] = MODULE_SERVICE
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_SERVICE
    elif table == "startupCommand":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_STARTUP_COMMAND
        scan_digest_dictionary["module"] = MODULE_STARTUP_COMMAND
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_STARTUP_COMMAND
    elif table == "usbController":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_USB_CONTROLLER
        scan_digest_dictionary["module"] = MODULE_USB_CONTROLLER
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_USB_CONTROLLER
    elif table == "userAccount":
        scan_digest_dictionary["objectidentifier"] = IDENTIFIER_USER_ACCOUNT
        scan_digest_dictionary["module"] = MODULE_USER_ACCOUNT
        scan_digest_dictionary["modlist"] = MODIFIER_LIST_USER_ACCOUNT
    else:
        debug_print("table {0} not found.".format(table))
        return False

    #scan_digest_dictionary = json.dumps(scan_digest_dictionary)
    return scan_digest_dictionary.copy()
    
"""    
scan_digest_final = get_scan_digest_for_scan_id("A-FATHI", 3, "service")
scan_digest_dictionary_final = generate_dictionary_for_scan_digest("A-FATHI", 3, scan_digest_final, "service")
#print(scan_digest_dictionary_final)
scan_digest_older = get_scan_digest_for_scan_id("A-FATHI", 2, "service")
scan_digest_dictionary_older = generate_dictionary_for_scan_digest("A-FATHI", 2, scan_digest_older, "service")
"""
#================================================================================================================================
#Step 3: compare between scan-ids with following actions:
#	- if in final but not in older >> added item
#	- if in older but not in final >> deleted item
#    - for duplicated items:
#        - if same scandigest, ignore
#        - if different scandigests >> modified item
#Step Input: older and final list of dictionaries per scan-id 
#Step Output: 3 list of dictionaries of data named (added_items, deleted_items and modified items)


def compare_scan_digests(final_dictionary, older_dictionary):
    print(f'Working On Hostname: [{final_dictionary["hostname"]}] And Table: {final_dictionary["table"]}')
    final_duplicated_items = {}
    older_duplicated_items = {}
    final_duplicated_items_list = []
    older_duplicated_items_list = []
    added_items = {}
    added_items_list = []
    deleted_items = {}
    deleted_items_list = []
    modified_items = {}
    modified_items_list = []
    for final_scan_digest in final_dictionary["scandigest_and_record_id_and_identifier"]:
        if str(final_scan_digest[-1]) == "None":
            continue

        new_item = True
        for older_scan_digest in older_dictionary["scandigest_and_record_id_and_identifier"]:
            if str(older_scan_digest[-1]) == "None":
                continue

            if final_scan_digest[-1] == older_scan_digest[-1]:
                final_duplicated_items["record-id"]  = final_scan_digest[0]
                #final_duplicated_items["scandigest"]  = final_scan_digest[1]
                final_duplicated_items["objectidentifier-value"]  = final_scan_digest[-1]
                final_duplicated_items["modifier-values"] = final_scan_digest
                final_duplicated_items["objectidentifier"]  = final_dictionary["objectidentifier"]
                final_duplicated_items["hostname"] = final_dictionary["hostname"]
                final_duplicated_items["scanid"] = final_dictionary["scanid"]
                final_duplicated_items["table"] = final_dictionary["table"]
                final_duplicated_items["module"] = final_dictionary["module"]
                final_duplicated_items_list.append(final_duplicated_items.copy())
                new_item = False
                break
        if new_item:
            # print("[+] New item FOUND!")
            # print(f"final_scan_digest:\n{final_scan_digest}")
            # print(f"older_scan_digest:\n{older_scan_digest}")
            # print(f"{final_scan_digest[-1]} == {older_scan_digest[-1]}")
            #added_items["scandigest"] = final_scan_digest[1]
            added_items["record-id"] = final_scan_digest[0]
            added_items["table"] = final_dictionary["table"]
            added_items["module"] = final_dictionary["module"]
            added_items["objectidentifier"] = final_dictionary["objectidentifier"]
            added_items["objectidentifier-value"] = final_scan_digest[-1]
            added_items["hostname"] = final_dictionary["hostname"]
            added_items["scanid"] = final_dictionary["scanid"]
            added_items_list.append(added_items.copy())


    for older_scan_digest in older_dictionary["scandigest_and_record_id_and_identifier"]:
        if str(older_scan_digest[-1]) == "None":
            continue

        deleted_item = True
        for final_scan_digest in final_dictionary["scandigest_and_record_id_and_identifier"]:
            if str(final_scan_digest[-1]) == "None":
                continue

            if final_scan_digest[-1] == older_scan_digest[-1]:
                older_duplicated_items["record-id"]  = older_scan_digest[0]
                #older_duplicated_items["scandigest"]  = older_scan_digest[1]
                older_duplicated_items["objectidentifier-value"]  = older_scan_digest[-1]
                older_duplicated_items["modifier-values"] = older_scan_digest
                older_duplicated_items["objectidentifier"]  = older_dictionary["objectidentifier"]
                older_duplicated_items["hostname"] = older_dictionary["hostname"]
                older_duplicated_items["scanid"] = older_dictionary["scanid"]
                older_duplicated_items["table"] = older_dictionary["table"]
                older_duplicated_items["module"] = older_dictionary["module"]
                older_duplicated_items_list.append(older_duplicated_items.copy())
                deleted_item = False
                break

        if deleted_item:
            # print("[+] Deleted item FOUND!")
            # print(f"final_scan_digest:\n{final_scan_digest}")
            # print(f"older_scan_digest:\n{older_scan_digest}")
            # print(f"{final_scan_digest[-1]} == {older_scan_digest[-1]}")

            #deleted_items["scandigest"] = older_scan_digest[1]
            deleted_items["record-id"] = older_scan_digest[0]
            deleted_items["table"] = older_dictionary["table"]
            deleted_items["module"] = older_dictionary["module"]
            deleted_items["objectidentifier"] = older_dictionary["objectidentifier"]
            deleted_items["objectidentifier-value"] = older_scan_digest[-1]
            deleted_items["hostname"] = older_dictionary["hostname"]
            deleted_items["scanid"] = older_dictionary["scanid"]
            deleted_items_list.append(deleted_items.copy())   
    #print(final_duplicated_items_list)
    mod_list = ",".join(final_dictionary["modlist"])
    find_modified_items_query = 'SELECT {0} FROM asset_inventory."{1}" where (scanid = {2} or scanid = {3}) and hostname = \'{4}\' group by {0} having count(*) = 1;'.format(mod_list, final_dictionary["table"], final_dictionary["scanid"], older_dictionary["scanid"], final_dictionary["hostname"])
    # print(f"[+] Modification Query:\n{find_modified_items_query}")
    modified_items_query_result = db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, find_modified_items_query)
    for modified_item in modified_items_query_result:
        for modified_item_2 in modified_items_query_result:
            # print(f"[+] Comparing -> {modified_item[-1]} == {modified_item_2[-1]}")
            if modified_item[-1] == modified_item_2[-1]:

                for counter in range (0, len(modified_item)):
                    modified_item_1_comparer = str(modified_item[counter])
                    modified_item_1_comparer = "None" if len(str(modified_item_1_comparer)) == 0 else modified_item_1_comparer

                    modified_item_2_comparer = str(modified_item_2[counter])
                    modified_item_2_comparer = "None" if len(str(modified_item_2_comparer)) == 0 else modified_item_2_comparer
                    # if modified_item[counter] != modified_item_2[counter]:
                    if modified_item_1_comparer != modified_item_2_comparer:
                        # print(f"[***] {modified_item[counter]} [{len(str(modified_item[counter]))}] != {modified_item_2[counter]} [{len(str(modified_item_2[counter]))}]")
                        try:
                            query_record_id, scanid, matchedScanId = scan_order_calculator(final_dictionary["modlist"], modified_item, older_dictionary["table"], older_dictionary["hostname"], older_dictionary["scanid"], final_dictionary["scanid"])
                        # print("[+] Modification Data Returned!")
                        except Exception as e:
                            print(f"[-] Error: {e}")
                            continue
                        if str(matchedScanId) == str(older_dictionary["scanid"]):
                            print(rf'[-] Modification Skipped: {str(matchedScanId)} == {str(older_dictionary["scanid"])}')
                            continue
                            #older_data = modified_item
                            #final_data = modified_item_2
                            #record_id = get_final_record_id(final_dictionary["modlist"] ,modified_item_2, older_dictionary["table"], older_dictionary["hostname"], final_dictionary["scanid"])
                            #record_id = older_dictionary["scanid"]
                            #print("Final Data:")
                            #print(final_data)
                        else:
                            # print("[+] Arranging In Else!")
                            older_data = modified_item_2
                            final_data = modified_item
                            record_id = query_record_id
                            #print("Final Data:")
                            #print(final_data)
                        modified_items["changedfield"] = final_dictionary["modlist"][counter]
                        modified_items["oldvalue"] = older_data[counter]
                        modified_items["newvalue"] = final_data[counter]
                        modified_items["record-id"] = record_id
                        # modified_items["scandigest"]  = final_modified_item["scandigest"]
                        try:
                            modified_items["objectidentifier-value"] = older_scan_digest[-1]
                        except:
                            modified_items["objectidentifier-value"] = final_scan_digest[-1]
                        modified_items["objectidentifier"]  = older_dictionary["objectidentifier"]
                        modified_items["hostname"] = older_dictionary["hostname"]
                        modified_items["scanid"] = final_dictionary["scanid"]
                        modified_items["table"] = older_dictionary["table"] 
                        modified_items["module"] = older_dictionary["module"]
                        # print("[+] Adding Modified Item To It's Related List.")
                        modified_items_list.append(modified_items.copy())
    return added_items_list, deleted_items_list, modified_items_list
            
"""          
added_items, deleted_items, modified_items = compare_scan_digests(scan_digest_dictionary_final, scan_digest_dictionary_older)
print(added_items)
print(deleted_items)
print(modified_items)
"""

#================================================================================================================================
#Step 4: insert data to table accordingly
#Step Input: add/deleted/modified items as list of dictionaries
#Step Output: data insertion to database 

def insert_items_to_database(added_items, deleted_items, modified_items, last_scan_id):
    if added_items:
        for added_value in range (0, len(added_items)):
            add_query = "INSERT INTO change_history.change_management (changedobject, changetype, objectidentifier, scanid, recordid, createdtime, hostname, modulename, objectidentifiervalue, lastscanid) VALUES ('{0}', '{1}', '{2}', {3}, {4}, '{5}', '{6}', '{7}', '{8}', '{9}');".format(added_items[added_value]["table"], "Add", added_items[added_value]["objectidentifier"], added_items[added_value]["scanid"], added_items[added_value]["record-id"],str(datetime.datetime.now()), added_items[added_value]["hostname"], added_items[added_value]["module"], added_items[added_value]["objectidentifier-value"], last_scan_id)
            db_insert_query(USER, PASSWORD, HOST, PORT, DATABASE, add_query)
            print(" [+] Data inserted as added-item for hostname = {0} on table = {1}.".format(added_items[added_value]["hostname"], added_items[added_value]["table"]))
    if deleted_items:
        for deleted_value in range (0, len(deleted_items)):
                del_query = "INSERT INTO change_history.change_management (changedobject, changetype, objectidentifier, scanid, recordid, createdtime, hostname, modulename, objectidentifiervalue, lastscanid) VALUES ('{0}', '{1}', '{2}', {3}, {4}, '{5}', '{6}', '{7}', '{8}', '{9}');".format(deleted_items[deleted_value]["table"], "Remove", deleted_items[deleted_value]["objectidentifier"], deleted_items[deleted_value]["scanid"], deleted_items[deleted_value]["record-id"],str(datetime.datetime.now()), deleted_items[deleted_value]["hostname"], deleted_items[deleted_value]["module"], deleted_items[deleted_value]["objectidentifier-value"], last_scan_id)
                db_insert_query(USER, PASSWORD, HOST, PORT, DATABASE, del_query)
                print(" [-] Data inserted as deleted-item for hostname = {0} on table = {1}.".format(deleted_items[deleted_value]["hostname"], deleted_items[deleted_value]["table"]))
    if modified_items:
        for modified_value in range (0, len(modified_items)):
                mod_query = "INSERT INTO change_history.change_management (changedobject, changetype, scanid, recordid, createdtime, hostname, changedfield, newvalue, oldvalue, modulename, objectidentifier, objectidentifiervalue, lastscanid) VALUES ('{0}', '{1}', {2}, {3}, '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}');".format(modified_items[modified_value]["table"], "Modify", modified_items[modified_value]["scanid"], modified_items[modified_value]["record-id"],str(datetime.datetime.now()), str(modified_items[modified_value]["hostname"]).replace("'","''"), str(modified_items[modified_value]["changedfield"]).replace("'","''"), str(modified_items[modified_value]["newvalue"]).replace("'","''") ,str(modified_items[modified_value]["oldvalue"]).replace("'","''"), str(modified_items[modified_value]["module"]).replace("'","''"), str(modified_items[modified_value]["objectidentifier"]), str(modified_items[modified_value]["objectidentifier-value"]), last_scan_id)
                db_insert_query(USER, PASSWORD, HOST, PORT, DATABASE, mod_query)
                print(" [*] Data inserted as modified-item for hostname = {0} on table = {1}.".format(modified_items[modified_value]["hostname"], modified_items[modified_value]["table"]))
    else:
        debug_print(" [!] No changes detected for hostname.")

#insert_items_to_database(added_items, deleted_items, modified_items)
#================================================================================================================================
#Step 5: execute change management procedures
#Step Input: all the created functions 
#Step Output: data insertion to database 

def get_last_change_history(hostname, last_scanid, table):
    scan_count_query = f"SELECT count(hostname) FROM \"change_history\".\"change_management\" where hostname = '{hostname}' and lastscanid={last_scanid} and changedobject='{table}'"
    try:
        scan_count = db_select_query(USER, PASSWORD, HOST, PORT, DATABASE, scan_count_query)
    except Exception as e:
        debug_print(f"[-] Error: {e}")
        return 0
    return int(scan_count[0][0])

def detect_added_item(target_info):
    added_objects = []

    scanid = target_info["scanid"]
    latest_scan_result = target_info[int(scanid)]
    older_scanid = target_info["older_scanid"]
    older_scan_result = target_info[older_scanid]

    object_identifier = target_info["objectidentifier"]

    for new_data in latest_scan_result:
        if str(new_data[object_identifier]).lower() == "none":
            continue

        new_item = True
        for old_data in older_scan_result:
            if str(new_data[object_identifier]).lower() == str(old_data[object_identifier]).lower():
                new_item = False
                break
        if new_item:
            added_object = {}
            added_object["changedobject"] = target_info["target_table"]
            added_object["changetype"] = "Add"
            added_object["objectidentifier"] = object_identifier
            added_object["changedobject"] = target_info["target_table"]
            added_object["hostname"] = target_info["hostname"]
            added_object["scanid"] = target_info["scanid"]
            added_object["lastscanid"] = older_scanid
            added_object["recordid"] = new_data["id"]
            added_object["changedfield"] = "N/A"
            added_object["oldvalue"] = "N/A"
            added_object["newvalue"] = "N/A"
            added_object["modulename"] = target_info["target_table"]
            added_object["objectidentifiervalue"] = new_data[object_identifier]
            added_object["createdtime"] = current_time()
            added_objects.append(added_object.copy())

    # print(added_items)
    return added_objects

def detect_deleted_item(target_info):
    json_target_info = json.dumps(target_info)
    # print(f"[!] Target Info:\n{json_target_info}")

    deleted_objects = []

    scanid = target_info["scanid"]
    latest_scan_result = target_info[int(scanid)]

    older_scanid = target_info["older_scanid"]
    older_scan_result = target_info[older_scanid]

    object_identifier = target_info["objectidentifier"]

    # print(f"[!] Latest Scan Result:\n{json.dumps(latest_scan_result)}")
    # print("----------")
    # print(f"[!] Older Scan Result:\n{json.dumps(older_scan_result)}")

    deleted_detected = []

    for old_data in older_scan_result:
        deleted_item = True

        old_data_value = old_data[object_identifier]

        for new_data in latest_scan_result:
            new_data_value = new_data[object_identifier]
            if str(old_data_value).lower() == str(new_data_value).lower():
                deleted_item = False
                break


        if deleted_item:
            if old_data[object_identifier] in deleted_detected:
                continue
            else:
                deleted_detected.append(old_data[object_identifier])
            deleted_object = {}
            deleted_object["changedobject"] = target_info["target_table"]
            deleted_object["changetype"] = "Delete"
            deleted_object["objectidentifier"] = object_identifier
            deleted_object["changedobject"] = target_info["target_table"]
            deleted_object["hostname"] = target_info["hostname"]
            deleted_object["scanid"] = target_info["scanid"]
            deleted_object["lastscanid"] = older_scanid
            deleted_object["recordid"] = old_data["id"]
            deleted_object["changedfield"] = "N/A"
            deleted_object["oldvalue"] = "N/A"
            deleted_object["newvalue"] = "N/A"
            deleted_object["modulename"] = target_info["target_table"]
            deleted_object["objectidentifiervalue"] = old_data[object_identifier]
            deleted_object["createdtime"] = current_time()
            deleted_objects.append(deleted_object)

    # print(deleted_items)
    return deleted_objects

def detect_modified_items(target_info):
    modified_objects = []

    scanid = target_info["scanid"]
    latest_scan_result = target_info[int(scanid)]
    older_scanid = target_info["older_scanid"]
    older_scan_result = target_info[older_scanid]

    object_identifier = target_info["objectidentifier"]

    """
    print(f"[target_info] {target_info}")
    print(f"[object_identifier] {object_identifier}")

    print(f"[!] Latest Scan Result:\n{json.dumps(latest_scan_result)}")
    print("----------")
    print(f"[!] Older Scan Result:\n{json.dumps(older_scan_result)}")
    """

    for latest_scan in latest_scan_result:
        # print(f"[latest_scan] {latest_scan}")
        last_scan_object_identifier = latest_scan[object_identifier]

        if str(last_scan_object_identifier).lower() in configurations["object_identifier_blacklist"] or \
                str(last_scan_object_identifier) in configurations["object_identifier_blacklist"] or \
                not str(last_scan_object_identifier).strip() or \
                len(str(last_scan_object_identifier)) < 1:
            continue

        for old_scan in older_scan_result:
            # print(f"[old_scan] {old_scan}")
            old_scan_object_identifier = old_scan[object_identifier]
            if last_scan_object_identifier == old_scan_object_identifier:
                for key in latest_scan.keys():
                    if str(key).lower() == "id" or str(key).lower() in configurations["blacklisted_items"]:
                        continue
                    else:
                        old_scan_data = old_scan[key]
                        if str(old_scan_data).lower() == "none":
                            continue
                        old_scan_data = str(old_scan_data).replace(",", "")

                        latest_scan_data = latest_scan[key]
                        if str(latest_scan_data).lower() == "none":
                            continue
                        latest_scan_data = str(latest_scan_data).replace(",", "")

                        if old_scan_data != latest_scan_data:
                            # print(latest_scan)
                            # print(old_scan)
                            # print("-------------")
                            modified_object = {}
                            modified_object["changedobject"] = target_info["target_table"]
                            modified_object["changetype"] = "Modify"
                            modified_object["objectidentifier"] = object_identifier
                            modified_object["changedobject"] = target_info["target_table"]
                            modified_object["hostname"] = target_info["hostname"]
                            modified_object["scanid"] = target_info["scanid"]
                            modified_object["lastscanid"] = older_scanid
                            modified_object["recordid"] = old_scan["id"]
                            modified_object["changedfield"] = key.lower()
                            modified_object["oldvalue"] = old_scan_data
                            modified_object["newvalue"] = latest_scan_data
                            modified_object["modulename"] = target_info["target_table"]
                            modified_object["objectidentifiervalue"] = latest_scan[object_identifier]
                            modified_object["createdtime"] = current_time()

                            modified_objects.append(modified_object.copy())
    return modified_objects

def execute_change_management_functions(table):
    print(f"[+] Checking Changes On Table [{table}].")
    parsed_hostname_and_id = get_hostname_and_scan_id(table)
    # parsed_hostname_and_id: [{'hostname': 'Saee.SB24.ir', 'scanid': 5, 'table': 'networkadapterconfiguration'}]

    for hostname_info in parsed_hostname_and_id:
        print(f"[!] Working on [{hostname_info['hostname']}].")
        hostname_info["target_table"] = table
        # Checking if previous scan has taken place with this exact "hostname", "scanid", "table"

        latest_scan_id = int(hostname_info["scanid"]) if hostname_info["scanid"] > 1 else 0

        # Check duplicate scan result
        check_duplicate_query = f"select * from change_history.change_management where hostname='{hostname_info['hostname']}' and scanid={latest_scan_id} and changedobject='{table}'"
        duplicate_result = database_handle.fetch_sql(check_duplicate_query)
        if duplicate_result:
            continue
        # Finish

        try:
            older_scanid = int(database_handle.get_older_scanid("asset_inventory", hostname_info["target_table"],
                                                      latest_scan_id, hostname_info["hostname"]))
        except Exception as e:
            # print(f"[+] {hostname_info['hostname']}] Has no older data... Skipped.")
            continue

        hostname_info["latest_scan_id"] = latest_scan_id
        hostname_info["older_scanid"] = older_scanid


        change_management_count = get_last_change_history(hostname_info["hostname"], latest_scan_id, table)
        if int(change_management_count) != 0:
            continue

        hostname_info = get_scan_digest_for_scan_id(hostname_info.copy(),
                                                    latest_scan_id)

        hostname_info = generate_dictionary_for_scan_digest(hostname_info.copy(),
                                                            latest_scan_id)

        hostname_info = get_scan_digest_for_scan_id(hostname_info.copy(),
                                                    older_scanid)

        # scan_digest_dictionary_older = generate_dictionary_for_scan_digest(hostname_info["hostname"],
        #                                                                    hostname_info["scanid"] - 1,
        #                                                                    scan_digest_older,
        #                                                                    table)
        # added_items = detect_added_item(hostname_info.copy())


        # print("[*] Checking for Added items...")
        if table not in configurations["added_blacklists"]:
            added_objects = detect_added_item(hostname_info.copy())
        else:
            added_objects = []

        # print("[*] Checking for Deleted items...")
        if table not in configurations["deleted_blacklists"]:
            deleted_objects = detect_deleted_item(hostname_info.copy())
        else:
            deleted_objects= []

        # print("[*] Checking for Modified items...")
        if table not in configurations["modified_blacklists"]:
            modified_objects = detect_modified_items(hostname_info.copy())
        else:
            modified_objects = []

        changed_objects = added_objects + deleted_objects + modified_objects
        # changed_objects = deleted_objects

        if changed_objects:
            # print(f"[!] changed_objects:\n{json.dumps(changed_objects)}")
            print(f"[+] Inserting [{len(changed_objects)}] Changed Objects In DB.")
            output_filename = "changed_data.csv"
            output_handle = open(output_filename, "w", encoding="utf-8", errors="ignore")

            column_names = database_handle.get_column_names("change_history", "change_management")
            column_names = [column[0] for column in column_names]
            # print(f"[!] column_names: {column_names}")

            headers_row = ",".join(column_names)
            output_handle.write(f"{headers_row}\n")

            for changed_object in changed_objects:
                # print(f"[!] changed_object: {changed_object}")
                changed_object["id"] = generate_new_GUID()
                insert_row = ""
                for column in column_names:
                    insert_row += f'{changed_object.get(column, "N/A")},'
                insert_row = insert_row[:-1]
                output_handle.write(f"{insert_row}\n")

            output_handle.close()
            try:
                database_handle.bulk2db("change_history", "change_management", output_filename)
            except Exception as e:
                print("[-] Failed to insert data into DB.")
                print(f"[Err] {e}")
                print(f"[ChangedData]:\n{json.dumps(changed_objects)}")


        # added_items, deleted_items, modified_items = compare_scan_digests(scan_digest_dictionary_final,
        #                                                                   scan_digest_dictionary_older)
        # insert_items_to_database(added_items,
        #                          deleted_items,
        #                          modified_items,
        #                          latest_scan_id)


def perform_change_management_on_all_tables():
    tbl_list = [
        "networkAdapterConfiguration",
        "bios",
        "systemDriver",
        "bootConfiguration",
        "cdromDrive",
        "computerSystem",
        "diskDrive",
        "group",
        "groupUser",
        "logicalDisk",
        "operatingSystem",
        "physicalMemory",
        "processor",
        "product",
        "quickFixEngineering",
        "startupCommand",
        "usbController",
        "userAccount",
        "service"
    ]
    # tbl_list = ['product']

    for tbl in tbl_list:
        execute_change_management_functions(tbl)

# sleep_time = 300
# while True:
if __name__ == "__main__":
    print(f"[!] ChangeManagement process started. ({current_time()})")
    perform_change_management_on_all_tables()
    print(f"[+] Finished checking for changes. ({current_time()})")
# print(f"[*] Sleeping for [{sleep_time}] Seconds.")
# time.sleep(sleep_time)
# execute_change_management_functions("networkAdapterConfiguration")
