import json
import sys
import datetime
import ipaddress
import uuid


def load_config():
    try:
        config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config = json.load(config_handle)
        config_handle.close()
        return config
    except Exception as e:
        print(f"[-] Failed to load config file.\n[Err] {e}")
        sys.exit(0)

def current_time():
    return str(datetime.datetime.now())[:19]

def ip2long(str_ipaddress):
    return int(ipaddress.ip_address(str_ipaddress))

def long2ip(int_ipaddress):
    return str(ipaddress.ip_address(int(int_ipaddress)))

def generate_new_GUID():
    uuidFour = uuid.uuid4()
    return uuidFour
