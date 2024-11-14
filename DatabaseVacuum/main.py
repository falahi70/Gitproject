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

current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")

query_end = ''' VACUUM FULL; '''
database_handle.execute_sql(query_end)

print(f"{current_time} SQL Commands Execute successfully")
