from netmiko import ConnectHandler
from random import randint
import requests
import re
import json
device = "192.168.242.203"
username = "admin"
password = "%TGBvfr4#EDCxsw2WERT"
device = {
    'device_type': 'cisco_ftd',
    'host': device,
    'username': username,
    'password': password,
}
try:
    ssh_connection = ConnectHandler(**device)
    print("Connected To Device")
except Exception as e:
    print("Connection To Device Hased Been Failed", str(e))
    exit()

try:
    output = ssh_connection.send_command("show arp")
    rawEntry = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",output)
    print (rawEntry)        
except Exception as e:
    print("Problem On command Output", str(e))
finally:
    ssh_connection.disconnect()

