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
print(scanid)