import createCategories
import unzipRenameFile
from modules.database_connections import *
from modules.general_functions import *
import calculateMaxScanId
import os
import pandas as pd
import time
import sys

sys.stdout.reconfigure(encoding='utf-8')

while True:
    config = load_config()
    deleteInventoryFolder("/CoreInspect/agents/LinuxInventory/", "InventoryData")
    directory_path = '/CoreInspect/agents/inventory_api'
    zip_files = [file for file in os.listdir(directory_path) if (file.endswith('.zip') and 'linux' in file.lower())]
    if len(zip_files)==0:
        print('No Job To Process')
        print('*************On Sleep********************')
        time.sleep(10)
        continue
		
    for file in zip_files:
        source_path = os.path.join(directory_path, file)
        cutprocessFile(source_path,"/CoreInspect/agents/LinuxInventory")

    directory_path = '/CoreInspect/agents/LinuxInventory/InventoryData'

    reanamepath = '/CoreInspect/agents/LinuxInventory'

    database_handle = databaseConnection(
        config["database_connection"]["hostname"],
        config["database_connection"]["username"],
        config["database_connection"]["password"],
        config["database_connection"]["db_name"]
    )

    unzipRenameFile.unzipFile('/CoreInspect/agents/LinuxInventory')

    max_scanid = calculateMaxScanId.calculateMaxScanId()

    createCategories.CategorySeprator('/CoreInspect/agents/LinuxInventory/extracted', max_scanid)

    if not (os.path.exists(directory_path) and os.path.isdir(directory_path)):
        print("The directory does not exist or is not a directory.")
    else:
        for filename in os.listdir(directory_path):
            if not filename.endswith('.csv'):
                continue
            csv_files = [file for file in os.listdir(directory_path) if file.endswith('.csv')]
            removeDuplicate(filename.split('.')[0], f'{directory_path}/{filename}')
            removeNullRecod(filename.split('.')[0], f'{directory_path}/{filename}')
            print(f'{filename} is Complete')
            if "startupCommand" in filename:
                df = pd.read_csv(f'{directory_path}/{filename}')
                df.rename(columns={'user': 'username'}, inplace=True)
                df.to_csv(f'{directory_path}/{filename}', index=False)
            csv_headers_array = get_csv_headers(f'{directory_path}/{filename}')
            tablename = filename.split('.')[0]
            database_handle.bulk2db(schema_name='asset_inventory',table_name=tablename,data_list=(directory_path +'/'+ filename ),csv_columns=csv_headers_array)

    #rename_directory_with_timestamp(reanamepath)
    csv_files = [file for file in os.listdir('/CoreInspect/agents/LinuxInventory/extracted') if file.endswith('.txt')]
    if len(csv_files)!=0:
        cutprocessfortxt('/CoreInspect/agents/LinuxInventory/extracted','/CoreInspect/agents/LinuxInventory/error')
	#process_json_files('/CoreInspect/agents/LinuxInventory/error')
    #cutprocessfortxt('/CoreInspect/agents/LinuxInventory/error','/CoreInspect/agents/LinuxInventory/extracted')
    print('*************On Sleep********************')
    time.sleep(10)
