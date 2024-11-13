from modules.general_functions import *
from modules.database_connections import *
import json
import sys



def load_config():
    try:
        config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config = json.load(config_handle)
        config_handle.close()
        return config
    except Exception as e:
        print(f"[-] Failed to read config file. ({current_time()})\n[Err] {e}")
        sys.exit(0)
config = load_config()

database_handle = Database(config["database"]["hostname"],
                           config["database"]["port"],
                           config["database"]["username"],
                           config["database"]["password"],
                           config["database"]["db_name"])

def get_target_schemas():
    schema_blacklist_name = config["blacklist_schema_keyword"]
    target_schema = []
    for schema in database_handle.get_schema_name():
        blacklist_hit = False
        for blacklist_name in schema_blacklist_name:
            if blacklist_name.lower() in schema.lower():
                blacklist_hit = True
        if not blacklist_hit:
            target_schema.append(schema)

    return target_schema

def add_new_osfamily(osfamily_list):
    osfamily_list = list(osfamily_list)
    current_os_family = config["fullscan_history_whitelist"].keys()
    for osfamily in osfamily_list:
        if osfamily.lower() not in current_os_family:
            config["fullscan_history_whitelist"][osfamily.lower()] = []
    appsettings_handle = open("appsettings.json", "w", encoding="utf-8", errors="ignore")
    json.dump(config, appsettings_handle)
    appsettings_handle.close()

def create_new_csv(target_details, output_filename, schema_name, table_name):
    csv_output_handle = open(output_filename, "w", encoding="utf-8", errors="ignore")
    headers = database_handle.get_column_name(schema_name, table_name)
    header_string = ",".join(headers)
    csv_output_handle.write(f"{header_string}\n")
    for target in target_details.copy():
        write_string = ""
        for header in headers:
            tmp_data = target.get(header, "0")
            write_string += f"{tmp_data},"
        write_string = write_string[:-1]
        csv_output_handle.write(f"{write_string}\n")
    csv_output_handle.close()

for schema in get_target_schemas():
    history_tablename = f"{schema.lower()}_scan_history"
    if not database_handle.is_table_exists("inventory_history", history_tablename):
        print(f"[*] Creating new table [{history_tablename}]. ({current_time()})")
        database_handle.create_default_table("inventory_history", history_tablename)

for schema_name in get_target_schemas():
    schema_table_names = database_handle.get_table_name(schema_name)
    schema_table_names.append("osfamily")
    for table_name in schema_table_names:
        if not database_handle.is_column_exists("inventory_history", f"{schema_name}_scan_history", table_name.lower()):
            blacklisted = False
            for blacklist_item in config["scanhistory_column_blacklist"]:
                if blacklist_item.lower() in table_name.lower():
                    blacklisted = True
            if not blacklisted:
                print(f"[+] Adding new column in [{schema_name}_scan_history]. ({current_time()}) [{table_name.lower()}]")
                database_handle.add_column("inventory_history", f"{schema_name}_scan_history", table_name.lower())



target_db = {}
osfamily_lists = set()
for schema_name in get_target_schemas():
    # if schema_name != "asset_inventory":
    #     continue
    print(f"[*] Getting {schema_name} data.")
    for table_name in database_handle.get_table_name(schema_name):

        # if table_name != "networkAdapterConfiguration":
        #     continue

        scan_history_schema_name = "inventory_history"
        scan_history_table_name = f"{schema_name.lower()}_scan_history"
        table_column_names = database_handle.get_column_name(schema_name, table_name)
        if "osfamily" not in table_column_names:
            query = f'SELECT hostname, MAX(scanid) FROM "{schema_name}"."{table_name}" GROUP By hostname;'
            try:
                hostname_scanid_pair = database_handle.get_query_result(query, single_column=False)
            except Exception as e:
                print(f"[-] Error on getting HostnameScanidOsfamily pair.\n[Err] {e}")
                continue

            for hostname, scanid in hostname_scanid_pair:
                if hostname not in target_db.keys():
                    target_db[hostname] = {}
                target_db[hostname][table_name.lower()] = scanid
                # osfamily_result = database_handle.get_osfamily(schema_name, table_name, hostname)
                # if osfamily_result:
                #     target_db[hostname]["osfamily"] = osfamily_result[0]
                #     osfamily_lists.add(osfamily_result[0])
                target_db[hostname]["schema_name"] = schema_name
                target_db[hostname]["table_name"] = table_name
                target_db[hostname]["scan_history_schema_name"] = scan_history_schema_name
                target_db[hostname]["scan_history_table_name"] = scan_history_table_name
        else:
            query = f'SELECT hostname, osfamily, MAX(scanid) FROM "{schema_name}"."{table_name}" GROUP By hostname, osfamily;'
            try:
                hostname_scanid_pair = database_handle.get_query_result(query, single_column=False)
            except Exception as e:
                print(f"[-] Error on getting HostnameScanidOsfamily pair.\n[Err] {e}")
                continue

            for hostname, osfamily, scanid in hostname_scanid_pair:
                if hostname not in target_db.keys():
                    target_db[hostname] = {}
                target_db[hostname][table_name.lower()] = scanid
                target_db[hostname]["osfamily"] = osfamily
                osfamily_lists.add(osfamily)
                target_db[hostname]["schema_name"] = schema_name
                target_db[hostname]["table_name"] = table_name
                target_db[hostname]["scan_history_schema_name"] = scan_history_schema_name
                target_db[hostname]["scan_history_table_name"] = scan_history_table_name
                target_db[hostname]["osfamily_scan_history_schema_name"] = scan_history_schema_name
                target_db[hostname]["osfamily_scan_history_table_name"] = scan_history_table_name

target_splited = {}
output_handle = open("debug0.json", "w", encoding="utf-8", errors="ignore")
json.dump(target_db.copy(), output_handle)
output_handle.close()
for hostname in target_db.keys():
    # if hostname != "Andishe-F5.SamanATM":
    #     continue
    # print(hostname)
    target_db[hostname]["hostname"] = hostname
    try:
        target_schema = target_db[hostname]["osfamily_scan_history_schema_name"]
        target_table = target_db[hostname]["osfamily_scan_history_table_name"]
    except Exception as e:
        target_schema = target_db[hostname]["scan_history_schema_name"]
        target_table = target_db[hostname]["scan_history_table_name"]
    if target_table not in target_splited.keys():
        target_splited[target_table] = []
    target_splited[target_table].append(target_db[hostname].copy())
# output_handle = open("debug.json", "w", encoding="utf-8", errors="ignore")
# json.dump(target_splited, output_handle)
# output_handle.close()
add_new_osfamily(osfamily_lists)
config = load_config()
print(f"[*] Found schemas: {target_splited.keys()}")

for target_schema in target_splited.keys():  # asset_inventory_scan_history
    print(f"[*] Working on {target_schema}")
    target_db = target_splited[target_schema]

    target_columns = target_db[0].keys()
    existing_columns = database_handle.get_column_name("inventory_history", f"{target_schema}")
    for column in target_columns:
        if column not in existing_columns:
            database_handle.add_column("inventory_history", f"{target_schema}", column.lower(), "varchar", "N/A")

    for target in target_db:
        osfamily = target.get("osfamily", "undefined").lower()
        scan_ids = []
        for whitelist_item in config["fullscan_history_whitelist"][osfamily]:
            returned_scanid = target.get(whitelist_item.lower(), 0)
            try:
                scan_ids.append(int(returned_scanid))
            except Exception as e:
                scan_ids.append(int(0))
        try:
            target["fullscan_history"] = min(scan_ids)
        except Exception as e:
            target["fullscan_history"] = 0
        target["updatedtime"] = current_time()
        target["id"] = generate_new_GUID()
        try:
            target["hostname"] = target.get("hostname").replace(",", ".")
        except Exception as e:
            continue
        target["osfamily"] = osfamily

    csv_output_filename = "output.csv"
    create_new_csv(target_db.copy(), csv_output_filename, "inventory_history", target_schema)
    database_handle.execute_query(f"Delete From inventory_history.\"{target_schema}\";")
    database_handle.bulk2db("inventory_history", target_schema, csv_output_filename)



# output_handle = open("debug.json", "w", encoding="utf-8", errors="ignore")
# json.dump(target_db, output_handle)
# output_handle.close()


