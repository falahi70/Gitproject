import pandas as pd
import json
import os
from pandas import json_normalize
from modules.general_functions import *
from modules.database_connections import *

config = load_config()

database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
    )

def CategorySeprator(file_path, max_scanid):
    json_directory = file_path
    files_in_directory = os.listdir(json_directory)
    json_files = [file for file in files_in_directory if file.endswith(".txt") and 'linux' in file.lower()]

    output_directory = '/CoreInspect/agents/LinuxInventory/InventoryData'
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    for json_file in json_files:
        hostname = json_file.split('___')[0]
        creattime = current_time()
        try:
            fetch_ipaddress_sql = f"select request_host from server_management.access_logs where request_hostname='{hostname}' order by created_time desc LIMIT 1"
            hostname_ipaddress = database_handle.fetch_sql(fetch_ipaddress_sql)[0][0]
            hostname_ipaddress = ip2long(str(hostname_ipaddress))
        except Exception as e:
            hostname_ipaddress = "0"

        json_file_path = os.path.join(json_directory, json_file)
        try:
            json_data = process_json_file(json_file_path)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            continue
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            continue

        if not json_data:
            print("JSON data is invalid or file is incomplete.")
            continue

        filtered_json_data = {root_name: root_data for root_name, root_data in json_data.items()
                              if root_data != {} and root_name != 'usbControllerDevice'}

        for root_name, root_data in filtered_json_data.items():
            if not root_data:
                continue
            try:
                df = json_normalize(root_data)
            except NotImplementedError:
                df = pd.DataFrame([root_data])

            df['hostname'] = hostname
            df["createdtime"] = creattime
            df["query"] = "N/A"
            df["scannedip"] = hostname_ipaddress
            df["osfamily"] = "Linux"

            maxScanId = max_scanid.get(root_name, None)
            default_value = 1
            df["scanid"] = maxScanId + 1 if maxScanId is not None else default_value

            csv_file_name = f'{root_name}.csv'
            csv_file_path = os.path.join(output_directory, csv_file_name)

            df.columns = [col.lower() if isinstance(col, str) else col for col in df.columns]

            tableColumnNamequery = f"SELECT column_name FROM information_schema.columns WHERE table_name = '{root_name}'"
            tableColumnName = database_handle.fetch_sql(tableColumnNamequery)
            tableColumnName = [row[0] for row in tableColumnName]

            columns_to_drop = [col for col in df.columns if col not in tableColumnName]
            df = df.drop(columns=columns_to_drop)

            df.to_csv(csv_file_path, mode='a', index=False, header=not os.path.exists(csv_file_path))

        try:
            os.remove(json_file_path)
            print(f'{json_file_path} deleted successfully.')
        except OSError as e:
            print(f'====Error deleting {json_file_path}: {e}')

