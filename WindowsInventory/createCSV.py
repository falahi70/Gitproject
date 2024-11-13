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

def createCSVFile(path):
    json_directory = path

    files_in_directory = os.listdir(json_directory)

    json_files = [file for file in files_in_directory if file.endswith(".txt")]

    group_dataframes = {}

    for json_file in json_files:
        hostname = json_file.split('_')[0]
        creattime = current_time()
        try:
            fetch_ipaddress_sql = f"select request_host from server_management.access_logs where request_hostname='{hostname}' order by created_time desc LIMIT 1"
            hostname_ipaddress = database_handle.fetch_sql(fetch_ipaddress_sql)[0][0]
            hostname_ipaddress = ip2long(str(hostname_ipaddress))
        except Exception as e:
            hostname_ipaddress = "0"
        json_file_path = os.path.join(json_directory, json_file)
        with open(json_file_path, 'r', encoding='utf-16') as file:
            print(json_file_path)
            try:
                json_data = json.load(file)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")
                continue
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        for root_name, root_data in json_data.items():
            if root_data != {}:
                if root_name != 'usbControllerDevice':
                    if root_name not in group_dataframes:
                        group_dataframes[root_name] = pd.DataFrame()
                    try:
                        if root_name != 'usbControllerDevice':
                            df = json_normalize(root_data)

                    except NotImplementedError:
                        df = pd.DataFrame([root_data])

                    df['hostname'] = hostname 
                    df["createdtime"] = creattime
                    df["query"] = "N/A"
                    df["scannedip"] = hostname_ipaddress
                    df["osfamily"] = "windows"
                    group_dataframes[root_name] = pd.concat([group_dataframes[root_name], df], ignore_index=True)

        try:
            os.remove(json_file_path)
            print(f'{json_file_path} deleted successfully.')
        except OSError as e:
            print(f'Error deleting {json_file_path}: {e}')

    output_directory = '/CoreInspect/agents/WindowsInventory/InventoryData'

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    try:
        for group_name, group_df in group_dataframes.items():
            csv_file_name = f'{group_name}.csv'
            csv_file_path = os.path.join(output_directory, csv_file_name)
            
            if os.path.exists(csv_file_path):
                existing_df = pd.read_csv(csv_file_path)
                # Concatenate the new data with existing data
                group_df = pd.concat([existing_df, group_df], ignore_index=True)

            group_df.columns = [col.lower() for col in group_df.columns]

            max_scanid = database_handle.get_max_scanid(schema_name='asset_inventory', table_name=group_name, hostname=hostname)

            default_value = 1

            group_df["scanid"] = max_scanid + 1 if max_scanid is not None else default_value

            group_df.to_csv(csv_file_path, index=False, header=True)
            
            print(f'{csv_file_name} created successfully.')

    except OSError as e:
        print(f'Error deleting {json_file_path}: {e}')


