from modules.coresolution import *
import json


coresolution_handle = coresolution("https",
                                   "192.168.161.35",
                                   "coreinspectapiuser",
                                   "Abcd123")
coresolution_handle.authenticate()

data = coresolution_handle.get_credential("snmpv2")
print(json.dumps(data))
