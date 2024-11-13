from modules.coresolution import *
from modules.database_connections import *
from modules.general_functions import *
import paramiko
import json
from multiprocessing.pool import ThreadPool
from datetime import datetime

start=datetime.now()
database_handle = databaseConnection(
                                        config["database_connection"]["database_hostname"],
                                        config["database_connection"]["database_username"],
                                        config["database_connection"]["database_password"],
                                        config["database_connection"]["database_dbname"]
                                    )

coresolution_handle = coresolution(
                                        config["coresolution_connection"]["scheme"],
                                        config["coresolution_connection"]["address"],
                                        config["coresolution_connection"]["username"],
                                        config["coresolution_connection"]["password"],
                                    )
paramiko.util.log_to_file('NUL')
fetched_credentials = {}
Errors = []
target_command = "cat /home/coreinspect/InventoryResult"
osfamily="Linux"
scanid = database_handle.get_max_scanid_by_osfamily('asset_inventory','operatingSystem',osfamily)
scanid = str(int(scanid or 0)+1)
coresolution_handle.authenticate()
successful_inserted_count = 0

targets = coresolution_handle.execute_cpl('|snippet \"linux Inventory\"')
print("[+] Device Targets Fetched Successfully.")

def get_all_credentials():
    global fetched_credentials

    def fetch_credential_data(credential_name):
        if credential_name not in fetched_credentials.keys():
            connection_data = coresolution_handle.get_connection(credential_name)
            credential_name = connection_data["credential"]["name"]
            credential_data = coresolution_handle.get_credential(credential_name)
            if credential_data:
                target_username = credential_data["username"]
                target_password = credential_data["password"]
            else:
                target_username = False
                target_password = False
            fetched_credentials[credential_name] = {"username": target_username,
                                                    "password": target_password}
        else:
            target_username = fetched_credentials[credential_name]["username"]
            target_password = fetched_credentials[credential_name]["password"]
        return target_username, target_password
    for target in targets:
        fetch_credential_data(target["cred"])
    print("[+] Credentials Fetched Successfully.\n")

def get_ssh_information(device_target):
    global Errors
    target_ipaddress = device_target["ipAddress"]
    target_port = device_target["port"]
    cred = device_target["cred"]
    target_hostname = device_target["hostName"]
    target_username = fetched_credentials[cred]["username"]
    target_password = fetched_credentials[cred]["password"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ipaddress, username=target_username, password=target_password,port=target_port, timeout=5)
    except Exception as e:
        print(f"[-] Failed SSH to {target_ipaddress}.\n\t[Err] {e}")
        Errors.append({
                        "hostname": target_hostname,
                        "ip": target_ipaddress,
                        "cred" : cred,
                        "port": target_port,
                        "error" : f"[-] Failed SSH to {target_ipaddress}.\n\t[Err] {e}"
                        })
        return 0

    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(target_command)
        command_output = ssh_stdout.read().decode(encoding="utf-8", errors="ignore").replace("'", " ")
        command_output = json.loads(command_output)
        ssh_error = ssh_stderr.read().decode(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[-] Failed Fetch Data By SSH From: {target_ipaddress}.\n\t[Err] {e}.\n\t\t[Err] {ssh_error}")
        Errors.append({
                        "hostname": target_hostname,
                        "ip": target_ipaddress,
                        "cred" : cred,
                        "port": target_port,
                        "error" : f"[-] Failed Fetch Data By SSH From: {target_ipaddress}.\n\t[Err] {e}.\n\t\t[Err] {ssh_error}"
                        })
        return 0
    ssh.close()
    return command_output #target_details.copy()

def generate_userAccount_query(ip,hostname,inventory_results):
    table_name  =  "userAccount"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["description"], inventory_result["fullname"], inventory_result["status"], inventory_result["domain"], inventory_result["sid"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,caption ,description ,fullname ,status ,domain ,sid ) VALUES " + values + ";"  
    return db_query
    
def generate_groupUser_query(ip,hostname,inventory_results):
    table_name  = "groupUser"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["groupcomponent"], inventory_result["partcomponent"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,groupcomponent ,partcomponent ) VALUES " + values + ";"
     
    return db_query

def generate_group_query(ip,hostname,inventory_results):
    table_name  = "group"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["description"], inventory_result["status"], inventory_result["domain"], inventory_result["sid"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,caption ,description ,status ,domain ,sid ) VALUES " + values + ";"
    return db_query

def generate_bootConfiguration_query(ip,hostname,inventory_results):
    table_name  = "bootConfiguration"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["bootdirectory"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,bootdirectory ) VALUES " + values + ";"
     
    return db_query

def generate_usbController_query(ip,hostname,inventory_results):
    table_name  = "usbController"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["caption"], inventory_result["manufacturer"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,caption ,manufacturer ) VALUES " + values + ";"
    return db_query

def generate_startupCommand_query(ip,hostname,inventory_results):
    table_name  = "startupCommand"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["command"], inventory_result["location"], inventory_result["user"], inventory_result["usersid"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,command, location, \"user\", usersid ) VALUES " + values + ";"
     
    return db_query

def generate_service_query(ip,hostname,inventory_results):
    table_name  = "service"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["pathname"], inventory_result["acceptstop"], inventory_result["startmode"], inventory_result["description"], inventory_result["displayName"], inventory_result["servicetype"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,caption, pathname, acceptstop, startmode, description, displayName, servicetype ) VALUES " + values + ";"
     
    return db_query

def generate_product_query(ip,hostname,inventory_results):
    table_name  =  "product"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["description"], inventory_result["installdate"], inventory_result["installlocation"], inventory_result["installsource"], inventory_result["vendor"], inventory_result["version"], inventory_result["packagename"], inventory_result["packagecode"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,caption ,description ,installdate ,installlocation ,installsource ,vendor, version ,packagename ,packagecode ) VALUES " + values + ";"
      
    return db_query

def generate_processor_query(ip, hostname, inventory_results):
    table_name = "processor"
    scannedip = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["deviceid"], \
                inventory_result["caption"], inventory_result["currentclockspeed"], inventory_result["l3cachesize"], \
                inventory_result["l2cachesize"], inventory_result["manufacturer"], inventory_result["maxclockspeed"], \
                inventory_result["numberoflogicalprocessors"], inventory_result["partnumber"], inventory_result["processorid"], inventory_result["socketdesignation"], inventory_result["threadcount"], inventory_result["virtualizationfirmwareenable"], inventory_result["numberofcores"]
        value = tuple(value)
        value = str(value)
        if values:
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,deviceid ,caption ,currentclockspeed ,l3cachesize ,l2cachesize ,manufacturer ,maxclockspeed, numberoflogicalprocessors ,partnumber, processorid, socketdesignation, threadcount, virtualizationfirmwareenabled, numberofcores ) VALUES " + values + ";"

    return db_query

def generate_physicalMemory_query(ip, hostname, inventory_results):
    table_name = "physicalMemory"
    scannedip = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in inventory_results:
        if  "GB" in inventory_result["capacity"]:
          capacity=inventory_result["capacity"].replace(" GB","")
          capacity=(((float(capacity)*1024)*1024)*1024)
        elif "MB" in inventory_result["capacity"]:
          capacity=inventory_result["capacity"].replace(" MB","")
          capacity=((float(capacity)*1024)*1024)
        else:
          capacity=inventory_result["capacity"]
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, str(int(capacity)), \
                inventory_result["caption"], inventory_result["configuredclockspeed"], inventory_result["datawidth"], \
                inventory_result["description"], inventory_result["devicelocator"], inventory_result["hotswappable"], \
                inventory_result["manufacturer"], inventory_result["partnumber"], inventory_result["serialnumber"],  inventory_result["speed"], inventory_result["tag"]
        value = tuple(value)
        value = str(value)
        if values:
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,capacity ,caption ,configuredclockspeed ,datawidth ,description ,devicelocator ,hotswappable, manufacturer ,partnumber, serialnumber, speed, tag ) VALUES " + values + ";"

    return db_query

def generate_networkAdapterConfiguration_query(ip,hostname,inventory_results):
    table_name  =  "networkAdapterConfiguration"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["ipaddress"], inventory_result["dnsdomain"], inventory_result["dnshostname"], inventory_result["interfaceindex"], inventory_result["macaddress"], inventory_result["description"], inventory_result["mtu"], inventory_result["ipsubnet"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,ipaddress ,dnsdomain ,dnshostname ,interfaceindex ,macaddress ,description ,mtu, ipsubnet ) VALUES " + values + ";"

    return db_query

def generate_logicalDisk_query(ip,hostname,inventory_results):
    table_name  =  "logicalDisk"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result
    for inventory_result in  inventory_results:
        if  "G" in inventory_result["size"]:
          size=inventory_result["size"].replace("G","")
          size=(((float(size)*1024)*1024)*1024)
        elif "M" in inventory_result["size"]:
          size=inventory_result["size"].replace("M","")
          size=((float(size)*1024)*1024)
        else:
          size=inventory_result["size"]
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["description"], inventory_result["volumename"], str(int(size)), inventory_result["filesystem"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,caption ,description ,volumename ,size ,filesystem  ) VALUES " + values + ";"

    return db_query

def generate_diskDrive_query(ip,hostname,inventory_results):
    table_name  =  "diskDrive"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        if  "G" in inventory_result["size"]:
          size=inventory_result["size"].replace("G","")
          size=(((float(size)*1024)*1024)*1024)
        elif "M" in inventory_result["size"]:
          size=inventory_result["size"].replace("M","")
          size=((float(size)*1024)*1024)
        else:
          size=inventory_result["size"]
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["manufacturer"], inventory_result["deviceid"], inventory_result["description"], str(int(size)), inventory_result["pnpdeviceid"], inventory_result["medialoaded"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,manufacturer ,deviceid ,description ,size ,pnpdeviceid ,medialoaded  ) VALUES " + values + ";"

    return db_query

def generate_bios_query(ip,hostname,inventory_results):
    table_name  =  "bios"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["caption"], inventory_result["description"], inventory_result["manufacturer"], inventory_result["version"], inventory_result["releasedate"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,caption ,description ,manufacturer ,version ,releasedate  ) VALUES " + values + ";"

    return db_query

def generate_computerSystem_query(ip,hostname,inventory_results):
    table_name  =  "computerSystem"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result



    for inventory_result in  inventory_results:
        if not "hypervisorpresent" in inventory_result:
            inventory_result["hypervisorpresent"] = inventory_result["virtualization"]
        if not "hypervisorpresent" in inventory_result:
            inventory_result["hypervisorpresent"] = "Unkown"

        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["dnshostname"], inventory_result["domain"], inventory_result["workgroup"], inventory_result["totalphysicalmemory"], inventory_result["systemskunumber"], inventory_result["primaryownername"], inventory_result["numberofprocessors"], inventory_result["numberoflogicalprocessors"], inventory_result["osMachineId"], inventory_result["manufacturer"] , inventory_result["hypervisorpresent"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,dnshostname ,domain ,workgroup ,totalphysicalmemory ,systemskunumber ,primaryownername, numberofprocessors ,numberoflogicalprocessors ,osMachineId, manufacturer, hypervisorpresent  ) VALUES " + values + ";"

    return db_query

def generate_operatingSystem_query(ip,hostname,inventory_results):
    table_name  =  "operatingSystem"
    scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(inventory_results, list)):
        liseted_result.append(inventory_results)
        inventory_results = liseted_result

    for inventory_result in  inventory_results:
    
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["buildNumber"], inventory_result["currentTimeZone"], inventory_result["installdate"], inventory_result["lastBootUpTime"], inventory_result["osArchitecture"], inventory_result["version"], inventory_result["serialNumber"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,caption ,buildNumber ,currentTimeZone ,installdate ,lastBootUpTime ,osArchitecture, version ,serialNumber ) VALUES " + values + ";"

    return db_query

def generate_Errors_query(errors):
    table_name  =  "error_results"
    #scannedip   = ip2long(ip)
    createdtime = current_time()

    value = ''
    values = ''

    liseted_result = []
    if not (isinstance(errors, list)):
        liseted_result.append(errors)
        errors = liseted_result

    for error in  errors:
        value = error["hostname"], error["ip"], error["error"].replace("'", " "), createdtime, "linux"
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO inventory_errors.\"{table_name}\" ( hostname  ,ipaddress ,message ,errortime, schemaname ) VALUES " + values + ";"

    return db_query

def is_there(name):
    if name  in Errors and (bool(Errors[name])): return 1
    else:  return 0

def insert_data(device_target):
    global Errors, successful_inserted_count
    target_ipaddress = device_target["ipAddress"]
    target_port = device_target["port"]
    cred = device_target["cred"]
    target_hostname = device_target["hostName"]
    inventory_result = get_ssh_information(device_target)
    hostname = inventory_result["computerSystem"].get("hostname", "N/A")
    caption = inventory_result["operatingSystem"].get("caption", "N/A")

    try:
        if "userAccount" in inventory_result and ( bool(inventory_result["userAccount"]) ):
            userAccount = generate_userAccount_query(device_target["ipAddress"], device_target["hostName"],inventory_result["userAccount"])
            print(userAccount)
        else:
            userAccount = ""

        if "groupUser" in inventory_result and ( bool(inventory_result["groupUser"]) ):
            groupUser = generate_groupUser_query(device_target["ipAddress"], device_target["hostName"],inventory_result["groupUser"])
            print(userAccount)
        else:
            groupUser  =   ""

        if "group" in inventory_result and ( bool(inventory_result["group"]) ) :
            group = generate_group_query(device_target["ipAddress"], device_target["hostName"],inventory_result["group"])
            print(group)
        else:
            group = ""

        if "bootConfiguration" in inventory_result  and ( bool(inventory_result["bootConfiguration"]) ):
            bootConfiguration = generate_bootConfiguration_query(device_target["ipAddress"], device_target["hostName"],inventory_result["bootConfiguration"])
            print(bootConfiguration)
        else:
            bootConfiguration = ""

        if "usbController" in inventory_result and ( bool(inventory_result["usbController"]) ) :
            usbController = generate_usbController_query(device_target["ipAddress"], device_target["hostName"],inventory_result["usbController"])
            print(usbController)
        else:
            usbController = ""

        if ("startupCommand" in inventory_result) and ( bool(inventory_result["startupCommand"]) ):
            startupCommand = generate_startupCommand_query(device_target["ipAddress"], device_target["hostName"],inventory_result["startupCommand"])
            print(startupCommand)
        else:
            startupCommand = ""

        if "service" in inventory_result and ( bool(inventory_result["service"]) ):
            service = generate_service_query(device_target["ipAddress"], device_target["hostName"],inventory_result["service"])
            print(service)
        else:
            service = ""

        if "product" in inventory_result and ( bool(inventory_result["product"]) ):
            product = generate_product_query(device_target["ipAddress"], device_target["hostName"],inventory_result["product"])
            print(product)
        else:
            product = ""

        if "processor" in inventory_result and ( bool(inventory_result["processor"]) ):
            processor = generate_processor_query(device_target["ipAddress"], device_target["hostName"],inventory_result["processor"])
            print(processor)
        else:
            processor = ""

        if "physicalMemory" in inventory_result and ( bool(inventory_result["physicalMemory"]) ):
            physicalMemory = generate_physicalMemory_query(device_target["ipAddress"], device_target["hostName"], inventory_result["physicalMemory"])
            print(physicalMemory)
        else:
            physicalMemory = ""

        if "networkAdapterConfiguration" in inventory_result and ( bool(inventory_result["networkAdapterConfiguration"]) ):
            networkAdapterConfiguration = generate_networkAdapterConfiguration_query(device_target["ipAddress"], device_target["hostName"], inventory_result["networkAdapterConfiguration"])
            print(networkAdapterConfiguration)
        else:
            networkAdapterConfiguration = ""

        if "logicalDisk" in inventory_result and ( bool(inventory_result["logicalDisk"]) ):
            logicalDisk = generate_logicalDisk_query(device_target["ipAddress"],device_target["hostName"],inventory_result["logicalDisk"])
            print(logicalDisk)
        else:
            logicalDisk = ""

        if "diskDrive" in inventory_result and ( bool(inventory_result["diskDrive"]) ):
            diskDrive = generate_diskDrive_query(device_target["ipAddress"],device_target["hostName"],inventory_result["diskDrive"])
            print(diskDrive)
        else:
            diskDrive = ""

        if "bios" in inventory_result and ( bool(inventory_result["bios"]) ):
            bios = generate_bios_query(device_target["ipAddress"],device_target["hostName"],inventory_result["bios"])
            print(bios)
        else:
            bios = ""

        if "computerSystem" in inventory_result and ( bool(inventory_result["computerSystem"]) ):
            computerSystem = generate_computerSystem_query(device_target["ipAddress"],device_target["hostName"],inventory_result["computerSystem"])
            print(computerSystem)
        else:
            computerSystem = ""

        if "operatingSystem" in inventory_result and ( bool(inventory_result["operatingSystem"]) ):
            operatingSystem = generate_operatingSystem_query(device_target["ipAddress"],device_target["hostName"],inventory_result["operatingSystem"])
            print(operatingSystem)
        else:
            operatingSystem = ""

        dbquery = userAccount + groupUser + group + bootConfiguration + usbController + startupCommand + service + product + processor + physicalMemory +networkAdapterConfiguration + logicalDisk + diskDrive + bios + computerSystem + operatingSystem

        database_handle.execute_sql(dbquery) # Insert Inventory Data To DB
        print("[+] Inserted Inventory Data Successfully For:\n\t", "IP Address:", target_ipaddress, "HostName:", hostname,caption)
        successful_inserted_count += 1
    except Exception as e:
        print(f"[-] Failed To Insert Data From {target_ipaddress}.\n\t[Err] {e}")
        Errors.append({
                        "hostname": target_hostname,
                        "ip": target_ipaddress,
                        "cred" : cred,
                        "port": target_port,
                        "error" : f"[-] Failed To Insert Data From {target_ipaddress}.\n\t[Err] {e}"
                        })

get_all_credentials()

number_of_targets = int(len(targets))
if number_of_targets >= 8 :thread_count = int(number_of_targets/8)
else: thread_count = 1
pool = ThreadPool(processes=thread_count)
while (targets):
    device_target = targets.pop()
    pool.apply_async(insert_data, (device_target,))
pool.close()  # Done adding tasks.
pool.join()  # Wait for all tasks to complete. Total

print ("====================FINISHED====================\n","\nDuration:",datetime.now()-start,"\nNumber Of Total:",  number_of_targets,"\nNumber Of Successfully Inserted:",successful_inserted_count)

if Errors : #!="":
    print("====================Errors====================\n")
    for Error in Errors :
        print(Error["error"])
    dbquery = generate_Errors_query(Errors)
    database_handle.execute_sql(dbquery)
    print("Number Of Failed:", (number_of_targets - successful_inserted_count))


"""
pool = ThreadPool(processes=8)
pool.map(insert_data,targets)

pool = ThreadPool(processes=8)
results = []
while (targets):
    device_target = targets.pop()
    results.append(pool.apply_async(generate_userAccount_query, (device_target["ipAddress"],device_target["hostName"],get_ssh_information(device_target["ipAddress"],device_target["port"],device_target["cred"])

pool = ThreadPool(processes=8)
results = []
while (targets):
    device_target = targets.pop()
    results.append(pool.apply_async(get_ssh_information, (device_target["ipAddress"],device_target["port"],device_target["cred"])))

pool.close()  # Done adding tasks.
pool.join()  # Wait for all tasks to complete.

"""




