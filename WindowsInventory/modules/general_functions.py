import json
import sys
import datetime
import ipaddress
import uuid
import csv
import os
import shutil
import pandas as pd

def load_config():
    try:
        config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config = json.load(config_handle)
        config_handle.close()
        return config
    except Exception as e:
        print(f"[-] Failed to load config file.\n[Err] {e}")
        sys.exit(0)

def current_time(filename=False):
    if not filename:
        return str(datetime.datetime.now())[:19]
    else:
        c_time = str(datetime.datetime.now())[:19]
        c_time = c_time.replace(" ", "")
        c_time = c_time.replace("-", "")
        c_time = c_time.replace(":", "")
        return c_time

def ip2long(str_ipaddress):
    return int(ipaddress.ip_address(str_ipaddress))

def long2ip(int_ipaddress):
    return str(ipaddress.ip_address(int(int_ipaddress)))

def generate_new_GUID():
    uuidFour = uuid.uuid4()
    uuidFour = str(uuidFour).replace("{", "").replace("}", "")
    return uuidFour

def get_csv_headers(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as csv_file:
        csv_reader = csv.reader(csv_file)
        headers = next(csv_reader)
    return headers

def rename_directory_with_timestamp(directory_path):

    folder_name = 'InventoryData'
    oldfolder = directory_path+"/"+folder_name
    current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    new_folder_name = f"{directory_path}/{folder_name}_{current_time}"
    
    try:
        os.rename(oldfolder,new_folder_name)
        print(f"{new_folder_name}")
    except Exception as e:
        print(f"{e}")


def copyprocess(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.zip')==True:
                shutil.copy(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def cutprocess(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.zip')==True:
                shutil.move(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def removeDuplicate(group_name,csv):
    try:
        csv_file_path = csv
        df = pd.read_csv(csv_file_path)

        if group_name in ("product", "bios", "diskDrive", "group", "logcalDisk", "printer",
                            "printerConfiguration"):
            if 'caption' in (df.columns):
                df.drop_duplicates(subset=['hostname', 'caption'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)
        elif group_name in ("bootConfiguration", "service", "startupCommand", "systemDriver", "userAccount"):
            if 'name' in (df.columns):    
                df.drop_duplicates(subset=['hostname', 'name'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)
        elif group_name in ("networkAdapter"):
            if 'interfaceindex'  in (df.columns):   
                df.drop_duplicates(subset=['hostname', 'interfaceindex'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("networkAdapterConfiguration"):
            if 'interfaceindex'  in (df.columns):
                df.drop_duplicates(subset=['hostname', 'interfaceindex'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("physicalMemory"):
            if 'devicelocator'  in (df.columns):
                df.drop_duplicates(subset=['hostname', 'devicelocator'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("quickFixEngineering"):
            if 'hotfixid'  in (df.columns):
                df.drop_duplicates(subset=['hostname', 'hotfixid'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("processor", "usbController"):
            if 'deviceid'  in (df.columns):    
                df.drop_duplicates(subset=['hostname', 'deviceid'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        else:
            df.drop_duplicates(subset=['hostname'], keep='last', inplace = True)
            df.to_csv(csv_file_path, index=False)

    except OSError as e:
        print(f'Error deleting {csv}: {e}')

def removeNullRecod(group_name,csv):
    try:
        csv_file_path = csv
        df = pd.read_csv(csv_file_path)

        if group_name in ("product", "bios", "diskDrive", "group", "logcalDisk", "printer",
                            "printerConfiguration"):
            if 'caption' in (df.columns):
                df.dropna(subset=['hostname', 'caption'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("bootConfiguration", "service", "startupCommand", "systemDriver", "userAccount"):
            if 'name' in (df.columns):
                df.dropna(subset=['hostname', 'name'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("networkAdapter"):
            if 'interfaceindex' in (df.columns):   
                df.dropna(subset=['hostname', 'interfaceindex'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("networkAdapterConfiguration"):
            if 'interfaceindex' in (df.columns):
                df.dropna(subset=['hostname', 'interfaceindex'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("physicalMemory"):
            if 'devicelocator' in (df.columns):    
                df.dropna(subset=['hostname', 'devicelocator'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("quickFixEngineering"):
            if 'hotfixid' in (df.columns):     
                df.dropna(subset=['hostname', 'hotfixid'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("processor", "usbController"):
            if 'deviceid' in (df.columns):    
                df.dropna(subset=['hostname', 'deviceid'], how='all')
                df.to_csv(csv_file_path, index=False)

        else:
            df.dropna(subset=['hostname'], how='all')
            df.to_csv(csv_file_path, index=False)

    except OSError as e:
        print(f'Error deleting {csv}: {e}')

def deleteInventoryFolder():
    current_directory = "/CoreInspect/agents/WindowsInventory"
    directory_to_delete = "InventoryData"
    path_to_delete = os.path.join(current_directory, directory_to_delete)
    if os.path.exists(path_to_delete):
        try:
            shutil.rmtree(path_to_delete)
            print(f'پوشه "{directory_to_delete}" با موفقیت حذف شد.')
        except Exception as e:
            print(f'خطا در حذف پوشه: {e}')
    else:
        print(f'پوشه "{directory_to_delete}" وجود ندارد.')