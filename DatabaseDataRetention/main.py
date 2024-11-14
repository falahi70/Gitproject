from modules.coresolution import *
from modules.database_connections import *
from modules.general_functions import *
import datetime

config = load_config()
database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)

with open('tables.json', 'r') as file:
    tables = json.load(file)

current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
for table_name, full_table_reference in tables.items():
    query =f'''WITH MaxScan AS (
                SELECT hostname, MAX(scanid) AS max_scanid
                FROM {full_table_reference}
                GROUP BY hostname
            )
            DELETE FROM {full_table_reference}
            WHERE (hostname, scanid) IN (
                SELECT s.hostname, s.scanid
                FROM {full_table_reference} s
                JOIN MaxScan ms ON s.hostname = ms.hostname
                WHERE s.scanid < ms.max_scanid - 10
            );'''
    try:
        database_handle.execute_sql(query)

    except Exception as e:
        print(f"Error deleting records from {full_table_reference}: {e}")
print(f"{current_time} Delete old records queries execute successfully")

#query_end = ''' VACUUM FULL; '''
#database_handle.execute_sql(query_end)

#print(f"{current_time} SQL Commands Execute successfully")
