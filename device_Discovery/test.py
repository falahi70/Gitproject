from modules.coresolution import *
import json


coresolution_handle = coresolution("https",
                                   "iam.mtnirancell.ir",
                                   "system",
                                   "1qaz!QAZ")
coresolution_handle.authenticate()

data = coresolution_handle.get_credential("mailUser")
print(json.dumps(data))
