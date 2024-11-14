import createCSV
import unzipRenameFile
from modules.database_connections import *
from modules.general_functions import *
import os
import pandas as pd
import time



config = load_config()
deleteInventoryFolder()
directory_path = '/CoreInspect/agents/inventory_api'
csv_files = [file for file in os.listdir(directory_path) if file.endswith('.zip')]
if len(csv_files)!=0:

    copyprocess(directory_path,"/CoreInspect/agents/WindowsInventory")

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
        
        tableColumnNamequery = f"SELECT column_name FROM information_schema.columns WHERE table_name = '{filename.split('.')[0]}'"
        
        
        tableColumnName = database_handle.fetch_sql(tableColumnNamequery)
        
        tableColumnName = [row[0] for row in tableColumnName]
        
        removeDuplicate(filename.split('.')[0],f'{directory_path}/{filename}')
        
        removeNullRecod(filename.split('.')[0],f'{directory_path}/{filename}')
        
        remove_non_matching_columns(f'{directory_path}/{filename}',tableColumnName)
        

        
        print(f'{filename} is Complate')
        '''
        if filename.endswith(".csv"):
            if "startupCommand" in filename:
                df = pd.read_csv(directory_path+"/"+filename)
                df.rename(columns={'user': 'username'}, inplace=True)
                df.to_csv(directory_path+"/"+filename, index=False)
            csv_headers_array = get_csv_headers(directory_path+"/"+filename)
        '''