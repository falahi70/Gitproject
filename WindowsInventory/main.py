import createCSV
import unzipRenameFile
from modules.database_connections import *
from modules.general_functions import *
import os
import pandas as pd
import time


while True:
    config = load_config()

    directory_path = '/CoreInspect/agents/inventory_api'
    csv_files = [file for file in os.listdir(directory_path) if file.endswith('.zip')]
    if len(csv_files)!=0:

        cutprocess("/CoreInspect/agents/inventory_api","/CoreInspect/agents/WindowsInventory")

        directory_path = '/CoreInspect/agents/WindowsInventory/InventoryData'

        reanamepath = '/CoreInspect/agents/WindowsInventory'

        database_handle = databaseConnection(
            config["database_connection"]["hostname"],
            config["database_connection"]["username"],
            config["database_connection"]["password"],
            config["database_connection"]["db_name"]
        )

        unzipRenameFile.unzipFile('/CoreInspect/agents/WindowsInventory')

        createCSV.createCSVFile('/CoreInspect/agents/WindowsInventory/extracted')

        for filename in os.listdir(directory_path):       
            csv_files = [file for file in os.listdir(directory_path) if file.endswith('.csv')]
            removeDuplicate(filename.split('.')[0],f'{directory_path}/{filename}')
            removeNullRecod(filename.split('.')[0],f'{directory_path}/{filename}')
            print(f'{filename} is Complate')
            if filename.endswith(".csv"):
                if "startupCommand" in filename:
                    df = pd.read_csv(directory_path+"/"+filename)
                    df.rename(columns={'user': 'username'}, inplace=True)
                    df.to_csv(directory_path+"/"+filename, index=False)
                csv_headers_array = get_csv_headers(directory_path+"/"+filename)
                tablename = filename.split('.')[0]
                database_handle.bulk2db(schema_name='asset_inventory',table_name=tablename,data_list=(directory_path +'/'+ filename ),csv_columns=csv_headers_array)
        rename_directory_with_timestamp(reanamepath)
    else:
        print('No Job To Process')
    time.sleep(360)

