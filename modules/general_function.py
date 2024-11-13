import os
import pandas
import re
import json
import sys
import datetime
import ipaddress
import uuid
import csv
import shutil
import tarfile
from modules.database import *


def load_config():
    try:
        config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config = json.load(config_handle)
        config_handle.close()
        return config
    except Exception as e:
        print(f"[-] Failed to load config file.\n[Err] {e}")
        sys.exit(0)
config = load_config()

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

def remove_first_line(pathoffile):

    for file in os.listdir(pathoffile):
            if (file!='AllConf.csv' and file.endswith(".csv")):

                filename="%s/%s"%(pathoffile,file)

                with open(filename, 'r', encoding='utf-8') as file:
                    reader = list(csv.reader(file))
                    if len(reader) > 0 and len(reader[0]) == 1:
                        lines = file.readlines()[1:]

                        with open(filename, 'w', encoding='utf-8') as file:
                            file.writelines(lines)

                        #print("First line deleted successfully.")

def read_and_clean_csv_headers(pathoffile):
    tablefileds = {}
    for file in os.listdir(pathoffile):
        if (file!='AllConf.csv' and  file.endswith(".csv")):
            tablname = str(file).replace(".csv","").lower()
            filepath = os.path.join(pathoffile, file)

            if os.path.getsize(filepath) == 0:
                print(f"{file} is empty.")
                continue

            df=pandas.read_csv(filepath)
            headers = df.columns

            cleaned_headers = []

            for header in headers:

                header = header.replace("#","number")

                header = re.sub(r'[^a-zA-Z0-9]', '', header)

                header = header.lower()

                cleaned_headers.append(header)
            

            tablefileds[tablname]=cleaned_headers
            df.columns = cleaned_headers

            df.to_csv(filepath, index=False)

    return tablefileds

def add_specific_fields(input_path, connection):
    createdtime = current_time()
    osfamily = config["osfamily"]
    schema_name = config["schema_name"]
    ip_address = "192.168.1.1"
    asset_ipaddress = ip2long(ip_address)
    for file in os.listdir(input_path):
        if (file!='AllConf.csv' and  file.endswith(".csv")):
            filepath = os.path.join(input_path, file)
            table = file.split('.')[0].lower()

            if os.path.getsize(filepath) == 0:
                continue

            df=pandas.read_csv(filepath)

            df['hostname'] = "device1"
            df["createdtime"] = createdtime
            df["query"] = "N/A"
            df["scannedip"] = asset_ipaddress
            df["osfamily"] = osfamily
            maxScanId = get_max_scanidnohost(connection, schema_name, table)
            default_value = 1
            df["scanid"] = maxScanId + 1 if maxScanId is not None else default_value
            df.to_csv(filepath, index=False)

def cutprocess(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.tgz')==True:
                shutil.move(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def cutprocessFile(file,newpath):
    try:
        shutil.move(file,newpath)
        print(f'file transfer was ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def extract_tgz(input_path:str, output_path:str):
    #try:
        with tarfile.open(input_path, "r:gz") as tar:
            csv_files = [member for member in tar.getmembers() if member.name.startswith("CSV/")]
            #tar.extractall(path=output_path, members=csv_files)
            for member in csv_files:
                member_path = os.path.relpath(member.name, "CSV")
                member.name = member_path
                tar.extract(member, path = output_path)
        print("csv files fetch from tgz file")
        os.remove(input_path)
        print("tgz file deleted successfully")
    #except Exception as e:
    #    print("Error in extract tgz file")

def copyprocess(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.tgz')==True:
                shutil.copy(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')
