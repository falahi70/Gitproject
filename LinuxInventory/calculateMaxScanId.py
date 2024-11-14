import pandas as pd
import json
import os
from pandas import json_normalize
from modules.general_functions import *
from modules.database_connections import *

config = load_config()

database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
	)

def calculateMaxScanId():
    max_scanid = {}
    print('***Start get Max scanid***')
    max_scanid['bios'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='bios')
    max_scanid['bootConfiguration'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='bootConfiguration')
    max_scanid['cdromDrive'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='cdromDrive')
    max_scanid['computerSystem'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='computerSystem')
    max_scanid['diskDrive'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='diskDrive')
    max_scanid['group'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='group')
    max_scanid['logicalDisk'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='logicalDisk')
    max_scanid['networkAdapter'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='networkAdapter')
    max_scanid['networkAdapterConfiguration'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='networkAdapterConfiguration')
    max_scanid['operatingSystem'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='operatingSystem')
    max_scanid['physicalMemory'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='physicalMemory')
    max_scanid['printer'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='printer')
    max_scanid['printerConfiguration'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='printerConfiguration')
    max_scanid['processor'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='processor')
    max_scanid['product'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='product')
    max_scanid['quickFixEngineering'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='quickFixEngineering')
    max_scanid['service'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='service')
    max_scanid['startupCommand'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='startupCommand')
    max_scanid['systemDriver'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='systemDriver')
    max_scanid['usbController'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='usbController')
    max_scanid['usbControllerDevice'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='usbControllerDevice')
    max_scanid['userAccount'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='userAccount')
    max_scanid['groupUser'] = database_handle.get_max_scanidnohost(schema_name='asset_inventory', table_name='groupUser')
    print('***End get Max scanid***')
    return max_scanid

