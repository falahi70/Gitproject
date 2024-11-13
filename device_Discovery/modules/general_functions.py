import json
import sys
import uuid
import ipaddress
import datetime
import psycopg2


def load_config():
    try:
        config = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config = json.load(config)
        return config
    except Exception as e:
        print("[-] Could not open config file.")
        print(f"[Err] {e}")
        sys.exit(0)

def db_connect():
    config = load_config()
    try:
        conn = psycopg2.connect(
            host=config["database_ipaddress"],
            database=config["database_dbname"],
            user=config["database_username"],
            password=config["database_password"])

        ps_cursor = conn.cursor()
    except Exception as e:
        print("[-] Failed To Connect To Database.")
        print(f"\t[Err] {e}")
        sys.exit(0)

    return conn, ps_cursor

def generate_new_GUID():
    uuidFour = str(uuid.uuid4())
    uuidFour = uuidFour.replace("}", "").replace("{", "")
    return uuidFour

def ip2long(str_ipaddress):
    return int(ipaddress.ip_address(str_ipaddress))

def long2ip(int_ipaddress):
    return str(ipaddress.ip_address(int(int_ipaddress)))

def current_time():
    return str(datetime.datetime.now())[:19]

def output_format(input):
    output = input.stdout.read()
    output = output.decode("utf-8", "ignore")
    return output

def return_json_line(line):
    line = line.split(", ", 2)
    data_dict = {}
    try:
        for data in line:
            key_value = data.split("=")
            key = key_value[0]
            value = key_value[1]
            while value[0] == " ":
                value = value[1:]
            data_dict[key] = value
            if key == "OID":
                oid_data = value.rsplit(".", 4)
                oid_data = f"{oid_data[-4]}.{oid_data[-3]}.{oid_data[-2]}.{oid_data[-1]}"
                data_dict["oid_data"] = oid_data

    except Exception as e:
        return {}
    return data_dict

def bulk2db(data_list, csv_name="data.csv", dump=False):
    def insert_csv_to_db(output_filename, schema_name, table_name):
        conn, cursor = db_connect()
        input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
        cursor.copy_expert(f"copy {schema_name}.{table_name} from STDIN CSV HEADER QUOTE '\"'", input_file_handle)
        conn.commit()
        conn.close()

    def create_csv(headers, values, outputname):
        output_handle = open(outputname, "w", encoding="utf-8", errors="ignore")

        header_str = ",".join(headers)
        output_handle.write(f"{header_str}\n")
        for value in values:
            value = [str(a) for a in value]
            value = [a.replace(",", "") for a in value]
            value_data = ",".join(value)
            output_handle.write(f"{value_data}\n")

        output_handle.close()

    headers = ["id", "network_node_key", "network_node_ipaddress", "ipaddress_string", "credential_profile",
               "credential_name", "hostname", "domain", "description", "status", "error", "scanid", "createdtime",
               "scan_type"]
    all_values = []
    for result_data in data_list:
        value = [
            result_data["id"],
            result_data.get("network_node_key", "N/A"),
            result_data.get("network_node_ipaddress", "N/A"),
            result_data.get("ipaddress_string", "N/A"),
            result_data.get("credential_profile", "N/A"),
            result_data.get("credential_name", "N/A"),
            result_data.get("hostname", "N/A"),
            result_data.get("domain", "N/A"),
            result_data.get("description", "N/A"),
            result_data.get("status", "N/A"),
            result_data.get("error", "N/A"),
            result_data.get("scanid", "N/A"),
            str(result_data.get("createdtime", "N/A")),
            result_data.get("scan_type", "N/A")
            ]
        all_values.append(value)
    print("[+] Creating CSV Results.")
    create_csv(headers, all_values, csv_name)
    print("[+] Inserting CSV Into DB.")
    if dump:
        print("[+] Saving results into file")
        file_handle = open(dump, "w", encoding="utf-8", errors="ignore")
        json.dump(data_list, file_handle)
        file_handle.close()
    insert_csv_to_db(csv_name, "device_discovery", "device_discovery")