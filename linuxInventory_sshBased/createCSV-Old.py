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
    
    print('***Start get Max scanid***')
    bios_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='bios')
    bootConfiguration_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='bootConfiguration')
    cdromDrive_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='cdromDrive')
    computerSystem_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='computerSystem')
    diskDrive_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='diskDrive')
    group_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='group')
    logicalDisk_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='logicalDisk')
    networkAdapter_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='networkAdapter')
    networkAdapterConfiguration_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='networkAdapterConfiguration')
    operatingSystem_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='operatingSystem')
    physicalMemory_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='physicalMemory')
    printer_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='printer')
    printerConfiguration_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='printerConfiguration')
    processor_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='processor')
    product_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='product')
    quickFixEngineering_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='quickFixEngineering')
    service_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='service')
    startupCommand_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='startupCommand')
    systemDriver_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='systemDriver')
    usbController_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='usbController')
    userAccount_max_scanid = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='userAccount')
    print('***End get Max scanid***')
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
        with open(json_file_path, 'r', encoding='utf-16-le') as file:
            print(json_file_path)
            print("==========================================================================")
            try:
                json_data = json.load(file)
            except json.JSONDecodeError as e:
                
                print(f"Error decoding JSON: {e}")
                continue
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        for root_name, root_data in json_data.items():
            if(root_name=='bootConfiguration'):
                max_scanid=bootConfiguration_max_scanid
            if (root_name== 'bios'):
                max_scanid=bios_max_scanid
            if (root_name== 'cdromDrive'):
                max_scanid=cdromDrive_max_scanid
            if (root_name=='group'):
                max_scanid=group_max_scanid
            if (root_name=='logicalDisk'):
                max_scanid=logicalDisk_max_scanid
            if (root_name=='networkAdapter'):
                max_scanid=networkAdapter_max_scanid
            if (root_name=='networkAdapterConfiguration_max_scanid'):
                max_scanid=networkAdapterConfiguration_max_scanid
            if (root_name=='operatingSystem'):
                max_scanid=operatingSystem_max_scanid
            if (root_name=='physicalMemory'):
                max_scanid=physicalMemory_max_scanid
            if (root_name=='print'):
                max_scanid=printer_max_scanid
            if (root_name=='printerConfiguration'):
                max_scanid=printerConfiguration_max_scanid
            if (root_name=='processor'):
                max_scanid=processor_max_scanid
            if (root_name=='product'):
                max_scanid=product_max_scanid
            if (root_name=='quickFixEngineering'):
                max_scanid=quickFixEngineering_max_scanid
            if (root_name=='service'):
                max_scanid=service_max_scanid
            if (root_name=='startupCommand'):
                max_scanid=startupCommand_max_scanid
            if (root_name=='systemDriver'):
                max_scanid=systemDriver_max_scanid
            if (root_name=='usbController'):
                max_scanid=usbController_max_scanid
            if (root_name=='userAccount'):
                max_scanid=userAccount_max_scanid
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
                    df["osfamily"] = "linux"
                    default_value = 1
                    df["scanid"] = max_scanid + 1 if max_scanid is not None else default_value
                    group_dataframes[root_name] = pd.concat([group_dataframes[root_name], df], ignore_index=True)

        try:
            os.remove(json_file_path)
            print(f'{json_file_path} deleted successfully.')
        except OSError as e:
            print(f'Error deleting {json_file_path}: {e}')

    output_directory = 'C:/Users/CoreInspect-User/CoreInspectAgent/linuxInventory/inventoryResultFiles/'

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

            group_df.to_csv(csv_file_path, index=False, header=True)
            
            print(f'{csv_file_name} created successfully.')

    except OSError as e:
        print(f'Error deleting {json_file_path}: {e}')


