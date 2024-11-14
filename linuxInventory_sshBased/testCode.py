import datetime
from modules.general_functions import sshConnection
import json
import os

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
                output = sshConnection(target_ip["ip"], target_ip["username"], target_ip["password"], "cat InventoryResult")
                output_dict = json.loads(output)
                hostname = output_dict["computerSystem"]["hostname"]
                filename = os.path.join(path, f"{hostname}_{formatted_datetime}.txt")
                with open(filename, "w", encoding="utf-16") as f:
                    f.write(json.dumps(output_dict))
            except  Exception as e:
                errip = target_ip["ip"]
                print(f"{e} \n {errip}")
                errordata = [errip, str(e)]
                with open(os.path.join(path, "errors", "errorip.csv"), "a", encoding="utf-16", newline='') as f:
                    f.write(",".join(errordata) + "\n") 
                filename = os.path.join(path, "errors", f"{errip}_{formatted_datetime}.txt")
                with open(filename, "w", encoding="utf-16") as f:
                    f.write(str(output))  
readInventoryResults([{"ip":"10.220.210.135", "username": "coreinspect", "password": "5ffsCS5eDW*Fvcz", "command": "cat InventoryResult"}],
                       "C:/Users/CoreInspect-User/CoreInspectAgent/linuxInventory/inventoryResultFiles")