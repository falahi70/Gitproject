import createCSV
from CoreDynamiX import *
from modules.database_connections import *
from modules.general_functions import *
import os
import pandas as pd
import time
import sys
import datetime

sys.stdout.reconfigure(encoding='utf-8')


config = load_config()

# In this step, before running the new Windows inventory, the previous data is deleted and the data inventory folder is created again.
current_directory = "/CoreInspect/agents/linuxInventory/"
directory_to_delete = "InventoryData"
deleteInventoryFolder(current_directory, directory_to_delete)

directory_path = '/CoreInspect/agents/linuxInventory/inventoryResultFiles'
reanamepath = '/CoreInspect/agents/linuxInventory'

# In this step, first the list of IPs is received from Coresolution, after that the InventoryResult file is read from each IP.
ipList =getLinuxIPs()
readInventoryResults(ipList, directory_path)

database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)

# In this step, csv file inventory is created for each database table in asset_inventory and the information of each IP is separated based on these categories and stored in these csvs.
createCSV.createCSVFile('/CoreInspect/agents/linuxInventory/inventoryResultFiles')

# In this step, run bulk insert for insert all data to database
directory_path = '/CoreInspect/agents/linuxInventory/InventoryData'
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

# In this step, InventoryData Folder name changed based on the time
#rename_directory_with_timestamp(reanamepath)

# In this step, the txt files that have errors are moved to the error folder
csv_files = [file for file in os.listdir('/CoreInspect/agents/linuxInventory/inventoryResultFiles') if file.endswith('.txt')]
if len(csv_files)!=0:
    cutprocessfortxt('/CoreInspect/agents/linuxInventory/inventoryResultFiles','/CoreInspect/agents/linuxInventory/error')
else:
    print('No Job To Process')


