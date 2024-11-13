
from modules.database_connections import *
import os

directory_path = '/CoreInspect/agents/inventory_api'
csv_files = [file for file in os.listdir(directory_path) if file.endswith('.zip')]
if len(csv_files)!=0:
    print("OKKKKKKKKKKK")



