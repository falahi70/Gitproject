import argparse
import json
import subprocess
import sys
from modules.database_connections import *
from modules.general_functions import *
from modules.coresolution import *
import main

config = load_config()
database_handle = databaseConnection(
    config["database_connection"]["host"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)

coresolution_handle = coresolution(
    config["coresolution"]["scheme"],
    config["coresolution"]["host"],
    config["coresolution"]["username"],
    config["coresolution"]["password"]
)
coresolution_handle.authenticate()

hostname= "95001HVBYW"
current_time()
sql_command = f"INSERT INTO \"server_management\".\"queue\" (\"hostname\", \"job\", \"queue_status\", \"db_status\", \"inventory_status\", \"filename\", \"created_time\", \"finished_time\") VALUES ('{hostname}', 'inventory', '0', '0', '0', 'N/A', '{current_time()}', '0000-00-00 00:00:00');"
database_handle.execute_sql(sql_command)
