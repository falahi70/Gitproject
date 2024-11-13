import sqlite3
import argparse
import json
import sys
import subprocess
import os
import time
import pandas as pd
import xlrd
import os
import re
import psycopg2
import socket
from decryptor import *
import getpass
import ipaddress
from modules.get_vcenter_info import vcenter_information_gathering

try:
    currentUser = getpass.getuser().split("\\")[-1]
    os.chdir(f'C:\\Users\\{currentUser}\\PowerVM')
except Exception as e:
    print(f"[-] Failed To Open PowerVM Folder.\n\t[Err] {e}")
    sys.exit(-1)
# os.chdir(f'C:\\Users\\{currentUser}\\PowerVM')
Tool_Directory = r"C:\Program Files (x86)\Robware\RVTools"
Output_File = rf"C:\users\{currentUser}\desktop\vcenter.xlsx"
# Output_File = r"C:\users\Mohammad.s\desktop\vcenter.xlsx"


parser = argparse.ArgumentParser(description="PowerVM VCenter Inventory")

parser.add_argument("-a", "--argument",
                    default="vmhost",
                    required=True,
                    help="Enter Your Argument To Fetch From Excel File (host | vmhost | vcenter)")

parser.add_argument("-vi", "--vcenter-ip",
                    default=False,
                    help="Enter VCenter IP Address To Fetch Information For")

parser.add_argument("-d", "--destination",
                    required=True,
                    help="Enter Your Target Computer Name Or IP Address")

parser.add_argument("-c", "--credential",
                    required=True,
                    help="Enter Your Credentials To Login With")

parser.add_argument("-v", "--verbose",
                    action="store_true",
                    default=False,
                    help="Show more verbose debug messages.")



options = parser.parse_args()

def verbose_print(message):
    if options.verbose:
        print(message)

if options.argument == "vcenter" and not options.vcenter_ip:
    print("[-] Please Specify VCenter IP Address Using -vi Switch.")
    sys.exit(-1)

try:
    conn = psycopg2.connect(
        host="localhost",
        database="CoreInspect",
        user="postgres",
        password="1234rewq!@#$REWQ")
    cursor = conn.cursor()
except Exception as e:
    print(f"[-] Database Connection Error.\n\t[Err] {e}")
    sys.exit(-1)


def output_format(input):
    output = input.stdout.read()
    output = output.decode("utf-8")
    try:
        res = json.loads(output)
    except:
        return output
    return res


if "." not in str(options.destination):
    try:
        options.destination = str(ipaddress.ip_address(int(options.destination)))
    except Exception as e:
        print(f"[-] Please Specify IP Address In Correct Format.\n\t[Err] {e}")
        sys.exit(-1)

verbose_print(f"[DBUG] Connecting To {options.destination}")


def Get_Creds(CredName):
    global VUsername
    global VString
    # query = f'SELECT username, password FROM "asset_inventory"."clixml" WHERE "name" = \'{CredName}\';'
    query = f'SELECT string FROM "asset_inventory"."clixml" WHERE "name" = \'{CredName}\';'
    cursor.execute(query)
    rows = cursor.fetchall()
    try:
        encrypted_data = rows[0][0]
    except Exception as e:
        print(f"[-] No Valid Credential Found.\n\t[Err] {e}")
        sys.exit(0)

    try:
        VUsername, VString = decrypt(encrypted_data).split(" || ")
        verbose_print(fr"[DBUG] Username: {VUsername}")
        verbose_print(fr"[DBUG] Password: {VString}")
    except Exception as e:
        print(f"[-] Failed To Decrypt Credential.\n\t[Err] {e}")
        sys.exit(-1)


def Create_Config(server, user, password, path):
    try:
        fin = open(fr"{Tool_Directory}\RVToolsBatchMultipleVCsTemplate.ps1", "rt")
        verbose_print(fr"[DBUG] Input Template: {Tool_Directory}\RVToolsBatchMultipleVCsTemplate.ps1")
        fout = open(fr"{Tool_Directory}\RVToolsVCs.ps1", "wt")
        verbose_print(fr"[DBUG] Output Template: {Tool_Directory}\RVToolsVCs.ps1")
    except Exception as e:
        print(f"[-] Failed To Create Config Files.\n\t{e}")
        sys.exit(-1)
    # domain, username = user.split("\\")
    # user = f"{username}@{domain}"
    for line in fin:
        line = line.replace("$ServerAddress$", server)
        line = line.replace("$ServerUser$", user)
        line = line.replace("$Serverpwd$", f'{password}')
        line = line.replace("$USERNAME$", path)
        line = line.replace("$currentuser$", currentUser)
        fout.write(line)


Get_Creds(options.credential)
try:
    Create_Config(options.destination, VUsername, VString, os.getlogin())
except Exception as e:
    print(f"[-] Error {e}")
    sys.exit(0)

command = rf"powershell.exe Get-Content '{Tool_Directory}\RVToolsVCs.ps1' | powerShell.exe -noprofile -"
verbose_print(fr"[DBUG] Command: {command}")
p = subprocess.Popen(command,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)
a = output_format(p)
vmhost_data = {}
host_data = {}
VNetowrk = {}
vNIC = {}
final_list = []

if not os.path.exists(Output_File):
    print("[-] Wrong Credential Used.")
    sys.exit(-1)


def Get_More():
    global VNetowrk
    if options.argument.lower() == "vmhost":
        sheetname = "vNetwork"
        df = pd.read_excel(Output_File, engine='openpyxl', sheet_name=sheetname)
        values = {"vNetworkName": 6,
                  "vNetworkSwitch": 7,
                  "vNetworkMacAddress": 10,
                  "vNetworkIP4Address": 12,
                  }
        for num in range(0, 1000):
            try:
                temp_dic = {}
                for key, value in values.items():
                    if str(df.iloc[num][value]) == "nan":
                        value = "Not Provided"
                    else:
                        value = str(df.iloc[num][value])
                    temp_dic[key] = value
                # print(temp_dic)
                temp_dic["vNetworkVMName"] = df.iloc[num][0]
                key = f"host{num}"
                VNetowrk[key] = temp_dic
            except Exception as e:
                break
    elif options.argument.lower() == "host":
        sheetname = "vNIC"
        df = pd.read_excel(Output_File, engine='openpyxl', sheet_name=sheetname)
        values = {"vNicDevice": 3,
                  "vNicMac": 7,
                  }
        for num in range(0, 1000):
            try:
                temp_dic = {}
                for key, value in values.items():
                    if str(df.iloc[num][value]) == "nan":
                        value = "Not Provided"
                    else:
                        value = str(df.iloc[num][value])
                    temp_dic[key] = value
                # print(temp_dic)
                key = f"host {df.iloc[num][0]} {df.iloc[num][3]}"
                vNIC[key] = temp_dic

            except:
                break


def Get_Data():
    global final_list
    if options.argument.lower() == "vmhost":
        sheetname = "vInfo"
        df = pd.read_excel(Output_File, engine='openpyxl', sheet_name=sheetname)
        values = {"vInfoGuestHostName": 6,
                  "vInfoNICs": 17,
                  "vInfoPrimaryIPAddress": 23,
                  "vInfoHost": 66,
                  "vInfoOSTools": 68,
                  "vInfoObjectID": 70}
        for num in range(0, 1000):
            try:
                temp_dic = {}
                for key, value in values.items():
                    if str(df.iloc[num][value]) == "nan":
                        value = "Not Provided"
                    else:
                        value = str(df.iloc[num][value])
                    temp_dic[key] = value
                # print(temp_dic)
                temp_dic["vInfoVMName"] = df.iloc[num][0]
                # print(VNetowrk)
                for key2, value2 in VNetowrk.items():
                    if df.iloc[num][0].lower() == value2['vNetworkVMName'].lower():
                        for f1, f2 in value2.items():
                            temp_dic[f1] = f2
                final_list.append(temp_dic)
                # key = f"host{num}"
                # vmhost_data[key] = temp_dic
            except:
                break
        vmhost_data["values"] = final_list

    elif options.argument.lower() == "host":
        sheetname = "vHost"
        df = pd.read_excel(Output_File, engine='openpyxl', sheet_name=sheetname)
        values = {"vHostCpuModel": 7,
                  "vHostCpuMhz": 8,
                  "vHostNumCpu": 11,
                  "vHostCoresPerCPU": 12,
                  "vHostNumCpuCores": 13,
                  "vHostMemorySize": 15,
                  "vHostFullName": 39,
                  "vHostModel": 51,
                  "vHostObjectID": 58,
                  "vHostServiceTag": 53,
                  }
        for num in range(0, 1000):
            try:
                temp_dic = {}
                for key, value in values.items():
                    if str(df.iloc[num][value]) == "nan":
                        value = "Not Provided"
                    else:
                        value = str(df.iloc[num][value])
                    temp_dic[key] = value
                # print(temp_dic)
                temp_dic["ip"] = df.iloc[num][0]
                for f1, f2 in vNIC.items():
                    if str(temp_dic["ip"]) in f1:
                        temp_dic[f2['vNicDevice']] = f2['vNicMac']
                final_list.append(temp_dic)
                # key = f"host{num}"
                # host_data[key] = temp_dic
            except:
                break
        host_data["values"] = final_list

    else:
        sheetname = ""
        print("Please Enter A Valid -a option")
        sys.exit(1)

if options.argument.lower() == "vcenter":
    vcenter_information = vcenter_information_gathering(options.vcenter_ip, Output_File)
    print(vcenter_information)

else:
    Get_More()
    Get_Data()

if options.argument != "vcenter":
    if host_data:
        for hostData in host_data["values"]:
            try:
                hostData["ip"] = socket.gethostbyname(hostData["ip"])
            except:
                continue

        host_data = str(host_data)
        host_data = re.sub('host\d+', 'host', host_data)
        host_data = host_data.replace("'", '"')
        print(host_data)
        for i in range(0, len(final_list)):
            data = final_list[i]
            sql = f"INSERT INTO vmware_inventory.esxi_inventory (vhost_cpu_model, vhost_cpu_mhz, vhost_num_cpu, vhost_cores_per_cpu, vhost_num_cpu_cores, vhost_memory_size, vhost_fullname, vhost_model, vhost_object_id, vhost_service_tag, ip, vmnic0, vmnic1, vmnic2, vmnic3, vmnic4, vmnic5) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);"
            val = (data["vHostCpuModel"], data["vHostCpuMhz"], data["vHostNumCpu"], data["vHostCoresPerCPU"],
                   data["vHostNumCpuCores"], data["vHostMemorySize"], data["vHostFullName"], data["vHostModel"],
                   data["vHostObjectID"], data["vHostServiceTag"], data["ip"], data["vmnic0"] if "vmnic0" in data.keys() else "", data["vmnic1"] if "vmnic0" in data.keys() else "",
                   data["vmnic2"] if "vmnic2" in data.keys() else "", data["vmnic3"] if "vmnic3" in data.keys() else "", data["vmnic4"] if "vmnic4" in data.keys() else "", data["vmnic5"] if "vmnic5" in data.keys() else "")
            cursor.execute(sql, val)
            conn.commit()
    else:
        for vmhostData in vmhost_data["values"]:
            try:
                vmhostData["vInfoHost"] = socket.gethostbyname(vmhostData["vInfoHost"])
            except:
                continue
        vmhost_data = str(vmhost_data)
        vmhost_data = re.sub('host\d+', 'host', vmhost_data)
        vmhost_data = vmhost_data.replace("'", '"')
        print(vmhost_data)

try:
    os.remove(fr"{Tool_Directory}\RVToolsVCs.ps1")
except Exception as e:
    pass

try:
    os.remove(Output_File)
except Exception as e:
    pass
