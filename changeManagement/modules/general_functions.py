import json
import datetime
import time
import uuid


def current_time():
    return str(datetime.datetime.now())[:19]

def load_config():
    config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
    config = json.load(config_handle)
    config_handle.close()
    return config

def generate_new_GUID():
    uuidFour = uuid.uuid4()
    return str(uuidFour)

