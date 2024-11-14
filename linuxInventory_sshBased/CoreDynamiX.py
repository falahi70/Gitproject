
from modules.coresolution import *
from modules.general_functions import *

def load_config():
    config_file = json.load(open("/CoreInspect/agents/linuxInventory/appsettings.json", "r", encoding="utf-8", errors="ignore"))
    return config_file

config_data = load_config()

coresolution_handle = coresolution(
    config_data["coresolution_scheme"],
    config_data["coresolution_ipaddress"],
    config_data["coresolution_username"],
    config_data["coresolution_password"])

coresolution_handle.authenticate()
def getLinuxIPs():
    linuxIPsList=coresolution.execute_cpl(self=coresolution_handle,cpl="|snippet \"linux Inventory\"")
    credList = []
    for linuxIP in linuxIPsList: #Create list Credential
        credList.append(linuxIP['cred'])

    credList = list(set(credList)) # remove duplicate Credential

    ipList = []
    for cred in credList:
        credentialData= coresolution.get_credential(coresolution_handle,cred)
        for linuxIP in  linuxIPsList:
            if linuxIP["cred"] == cred:
                ip = {
                        "ip":linuxIP["ipAddress"],
                        "port":linuxIP["port"],
                        "hostname":linuxIP["hostName"],
                        "ipNumber":ip2long(linuxIP["ipAddress"]),
                        "credName":linuxIP["cred"],
                        "username":credentialData["username"],
                        "password":credentialData["password"],
                    }
                ipList.append(ip)
    return ipList
