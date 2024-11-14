import json
import sys
import datetime
import ipaddress
import uuid
import csv
import os
import shutil
import pandas as pd
import netmiko

def load_config():
    try:
        config_handle = open("/CoreInspect/agents/DatabaseVacuum/appsettings.json", "r", encoding="utf-8", errors="ignore")
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
        
def cutprocessfortxt(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.txt')==True:
                shutil.move(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def removeDuplicate(group_name,csv):
    try:
        csv_file_path = csv
        df = pd.read_csv(csv_file_path,low_memory=False)    
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
        df = pd.read_csv(csv_file_path,low_memory=False)

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
        
def remove_non_matching_columns(csv_filename, table_column_names):
    try:
        # بررسی وجود فایل CSV
        with open(csv_filename):
            pass
    except FileNotFoundError:
        print(f"Error: File '{csv_filename}' not found!")
        return

    try:
        # خواندن هدرهای فایل CSV
        csv_headers = pd.read_csv(csv_filename, nrows=1).columns.tolist()
    except pd.errors.EmptyDataError:
        print(f"Error: No header found in '{csv_filename}'!")
        return

    # بررسی تطابق هدرهای فایل CSV با نام‌های ستون‌های جدول
    non_matching_columns = [col for col in csv_headers if col not in table_column_names]

    # اگر هدرهایی وجود داشته باشند که در لیست مشخص نیستند، حذف می‌شوند
    if non_matching_columns:
        try:
            # حذف هدرهای غیرمطابق
            df_filtered = pd.read_csv(csv_filename).drop(columns=non_matching_columns)

            # ذخیره DataFrame به فایل CSV
            df_filtered.to_csv(csv_filename, index=False)
            print("Non-matching columns removed successfully.")
        except Exception as e:
            print(f"Error occurred while removing non-matching columns: {e}")
    else:
        print("No non-matching columns found.")

def deleteInventoryFolder(current_directory, directory_to_delete):
    path_to_delete = os.path.join(current_directory, directory_to_delete)
    if os.path.exists(path_to_delete):
        try:
            shutil.rmtree(path_to_delete)
            print(f'پوشه "{directory_to_delete}"Delete Success')
        except Exception as e:
            print(f'خطا در حذف پوشه: {e}')
    else:
        print(f'پوشه "{directory_to_delete}" No Folder')

def sshConnection(ip,userName,password,command,port):
    try:
        device = {
            'device_type': 'linux',
            'ip': ip,
            'port': port,
            'username': userName,
            'password': password,
            'conn_timeout': 30,
        }
        ssh_client = netmiko.ConnectHandler(**device)
        output=ssh_client.send_command(command, read_timeout=40)
        """output = {"commandoutput":output,
                  "error":None,
                    "status" : 1}"""
    except netmiko.NetmikoAuthenticationException:
        print("Authentication Fail")
        output = {  "commandoutput":None,
                    "error":"Authentication Fail",
                    "status" : 0}
    except netmiko.NetmikoTimeoutException as e:
        print(f"Fail SSH: {str(e)}")
        output = {"commandoutput":None,
                    "error":{str(e)},
                    "status" : 0}
    except Exception as e:
        print(f"Fail: {str(e)}")
        output = {"commandoutput":None,
                  "error":{str(e)},
                  "status" : 0}
    finally:
        if 'ssh_client' in locals():
            ssh_client.disconnect()
    return output


def readInventoryResults(ipList, path):
    current_datetime = datetime.datetime.now()
    formatted_datetime = current_datetime.strftime("%Y-%m-%d")
    if len(ipList) > 0:
        for target_ip in ipList:
            try:
                print(target_ip["ip"])
                errorsPath = os.path.join(path, "errors")
                if not os.path.exists(errorsPath):
                    os.makedirs(errorsPath)
                output = sshConnection(target_ip["ip"], target_ip["username"], target_ip["password"], "cat InventoryResult", target_ip["port"])
                output_dict = json.loads(output)
                hostname = output_dict["computerSystem"]["hostname"]
                ip = target_ip["ip"]
                filename = os.path.join(path, f"{hostname}_{ip}_{formatted_datetime}.txt")
                with open(filename, "w", encoding="utf-16") as f:
                    f.write(json.dumps(output_dict))
            except  Exception as e:
                errip = target_ip["ip"]
                print(f"{e} \n {errip}")
                errordata = [errip, str(e)]
                with open(os.path.join(path, "errors", "errorip.csv"), "a", encoding="utf-16", newline='') as f:
                    f.write(",".join(errordata) + "\n") 
                filename = os.path.join(path, "errors", f"{errip}.txt")
                with open(filename, "w", encoding="utf-16") as f:
                    f.write(str(output))
