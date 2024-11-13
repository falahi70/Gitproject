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
Errors = ""
target_command = "cat /home/coreinspect/InventoryResult"
osfamily="Linux"
scanid = database_handle.get_max_scanid_by_osfamily('asset_inventory','operatingSystem',osfamily)
scanid = str(int(scanid)+1)
coresolution_handle.authenticate()
successful_inserted_count = 0

targets = coresolution_handle.execute_cpl("""
                                                | search        resourceType = "device"
                                                            and operatingSystemType = "Linux"
                                                | fields        key     as      device,
                                                                defaultNetworkNode, hostname , 
                                                                @credential     as      cred
                                                               
                                                | join          @outer.defaultNetworkNode  = @inner.defaultNetworkNode
                                                                [
                                                                    | search        resourceType = "networkNode"
                                                                    | fields        key         as  defaultNetworkNode,
                                                                                    ipAddress
                                                                ]
                                                | eval          ipAddress   :=  longtoip(ipAddress),
                                                                ipAddress   :=  tostring(ipAddress)    
                                                | join  type := left @outer.ipAddress = @inner.ipaddress
                                                        [
                                                            | datasource "connection_method_discovery_connectionMethod"
                                                            | fields ipaddress, discoveredConnectionMethod,openPort
                                                        ]                
                                                
                                                | eval openPort :=  tonumber(openPort)
                                                | eval query := "cat  /home/coreinspect/InventoryResult" //"cat /home/CoreInspect/InventoryResult"
                                                | eval   port :=  if(openPort=null , 22 ,openPort )
                                                | fields    ipAddress , cred , hostname, port
                                         
                                            """)
print("[+] Device Targets Fetched Successfully.")

def get_all_credentials():
    global fetched_credentials
    def fetch_credential_data(credential_name):
        if credential_name not in fetched_credentials.keys():
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

def get_ssh_information(ip,port,cred):
    global Errors
    target_ipaddress = ip
    target_port = port
    target_username = fetched_credentials[cred]["username"]
    target_password = fetched_credentials[cred]["password"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ipaddress, username=target_username, password=target_password,port=target_port, timeout=5)
    except Exception as e:
        print(f"[-] Failed SSH to {target_ipaddress}.\n\t[Err] {e}")
        Errors += f"[-] Failed SSH To {target_ipaddress}.\n\t[Err] {e}\n"
        return 0

    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(target_command)
        command_output = ssh_stdout.read().decode(encoding="utf-8", errors="ignore").replace("'"," ")
        command_output = json.loads(command_output)
        ssh.close()
    except Exception as e:
        print(f"[-] Failed Fetch SSH Data From: {target_ipaddress}.\n\t[Err] {e}")
        Errors += f"[-] Failed Fetch SSH Data From: {target_ipaddress}.\n\t[Err] {e}\n"
        return 0

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
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["capacity"], \
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
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["caption"], inventory_result["description"], inventory_result["volumename"], inventory_result["size"], inventory_result["filesystem"]
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
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["manufacturer"], inventory_result["deviceid"], inventory_result["description"], inventory_result["size"], inventory_result["pnpdeviceid"], inventory_result["medialoaded"]
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
        value = target_command, scannedip, osfamily, hostname, scanid, createdtime, inventory_result["name"], inventory_result["dnshostname"], inventory_result["domain"], inventory_result["workgroup"], inventory_result["totalphysicalmemory"], inventory_result["systemskunumber"], inventory_result["primaryownername"], inventory_result["numberofprocessors"], inventory_result["numberoflogicalprocessors"], inventory_result["osMachineId"], inventory_result["manufacturer"], inventory_result["hypervisorpresent"]
        value = tuple(value)
        value = str(value)
        if values :
            values += f" , " + value
        else:
            values += value

    db_query = f"INSERT INTO asset_inventory.\"{table_name}\" ( query, scannedip  ,osfamily ,hostname ,scanid ,createdtime,name ,dnshostname ,domain ,workgroup ,totalphysicalmemory ,systemskunumber ,primaryownername, numberofprocessors ,numberoflogicalprocessors ,osMachineId,manufacturer ,hypervisorpresent  ) VALUES " + values + ";"

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

def insert_data(device_target):
    global Errors, successful_inserted_count
    target_ipaddress    =   device_target["ipAddress"]
    inventory_result = get_ssh_information(device_target["ipAddress"],device_target["port"],device_target["cred"])
    hostname = inventory_result["computerSystem"].get("hostname", "N/A")
    caption = inventory_result["operatingSystem"].get("caption", "N/A")

    try:
        if "userAccount" in inventory_result and ( bool(inventory_result["userAccount"]) ):
            userAccount = generate_userAccount_query(device_target["ipAddress"], device_target["hostName"],inventory_result["userAccount"])
        else:
            userAccount = ""

        if "groupUser" in inventory_result:
            groupUser = generate_groupUser_query(device_target["ipAddress"], device_target["hostName"],inventory_result["groupUser"])
        else:
            groupUser  =   ""

        if "group" in inventory_result:
            group = generate_group_query(device_target["ipAddress"], device_target["hostName"],inventory_result["group"])
        else:
            group = ""

        if "bootConfiguration" in inventory_result:
            bootConfiguration = generate_bootConfiguration_query(device_target["ipAddress"], device_target["hostName"],inventory_result["bootConfiguration"])
        else:
            bootConfiguration = ""

        if "usbController" in inventory_result:
            usbController = generate_usbController_query(device_target["ipAddress"], device_target["hostName"],inventory_result["usbController"])
        else:
            usbController = ""

        if ("startupCommand" in inventory_result) and ( bool(inventory_result["startupCommand"]) ):
            startupCommand = generate_startupCommand_query(device_target["ipAddress"], device_target["hostName"],inventory_result["startupCommand"])
        else:
            startupCommand = ""

        if "service" in inventory_result:
            service = generate_service_query(device_target["ipAddress"], device_target["hostName"],inventory_result["service"])
        else:
            service = ""

        if "product" in inventory_result:
            product = generate_product_query(device_target["ipAddress"], device_target["hostName"],inventory_result["product"])
        else:
            product = ""

        if "processor" in inventory_result:
            processor = generate_processor_query(device_target["ipAddress"], device_target["hostName"],inventory_result["processor"])
        else:
            processor = ""

        if "physicalMemory" in inventory_result:
            physicalMemory = generate_physicalMemory_query(device_target["ipAddress"], device_target["hostName"], inventory_result["physicalMemory"])
        else:
            physicalMemory = ""

        if "networkAdapterConfiguration" in inventory_result:
            networkAdapterConfiguration = generate_networkAdapterConfiguration_query(device_target["ipAddress"], device_target["hostName"], inventory_result["networkAdapterConfiguration"])
        else:
            networkAdapterConfiguration = ""

        if "logicalDisk" in inventory_result:
            logicalDisk = generate_logicalDisk_query(device_target["ipAddress"],device_target["hostName"],inventory_result["logicalDisk"])
        else:
            logicalDisk = ""

        if "diskDrive" in inventory_result:
            diskDrive = generate_diskDrive_query(device_target["ipAddress"],device_target["hostName"],inventory_result["diskDrive"])
        else:
            diskDrive = ""

        if "bios" in inventory_result:
            bios = generate_bios_query(device_target["ipAddress"],device_target["hostName"],inventory_result["bios"])
        else:
            bios = ""

        if "computerSystem" in inventory_result:
            computerSystem = generate_computerSystem_query(device_target["ipAddress"],device_target["hostName"],inventory_result["computerSystem"])
        else:
            computerSystem = ""

        if "operatingSystem" in inventory_result:
            operatingSystem = generate_operatingSystem_query(device_target["ipAddress"],device_target["hostName"],inventory_result["operatingSystem"])
        else:
            operatingSystem = ""

        dbquery = userAccount + groupUser + group + bootConfiguration + usbController + startupCommand + service + product + processor + physicalMemory +networkAdapterConfiguration + logicalDisk + diskDrive + bios + computerSystem + operatingSystem

        database_handle.execute_sql(dbquery) # Insert Inventory Data To DB
        print("[+] Inserted Inventory Data Successfully For:\n\t", "IP Address:", target_ipaddress, "HostName:", hostname,caption)
        successful_inserted_count += 1
    except Exception as e:
        print(f"[-] Failed To Insert Data From {target_ipaddress}.\n\t[Err] {e}")
        Errors += f"[-] Failed To Insert Data From {target_ipaddress}.\n\t[Err] {e}\n"

get_all_credentials()

number_of_targets = int(len(targets))
thread_count = int(number_of_targets/8)
pool = ThreadPool(processes=thread_count)
while (targets):
    device_target = targets.pop()
    pool.apply_async(insert_data, (device_target,))
pool.close()  # Done adding tasks.
pool.join()  # Wait for all tasks to complete. Total

print ("====================FINISHED====================\n","\nDuration:",datetime.now()-start,"\nNumber Of Total:",  number_of_targets,"\nNumber Of Successfully Inserted:",successful_inserted_count)

if Errors !="":
    print("====================Errors====================\n", Errors , "\nNumber Of Failed:", (number_of_targets - successful_inserted_count))

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




