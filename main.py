from modules.general_function import *
from modules.database import *

config = load_config()
input_path = config["input_path"]
base_path = config["base_path"]
archive_path = f"{base_path}/archive"

connection = psycopg2.connect(
    dbname=config["database_connection"]["db_name"],
    user=config["database_connection"]["username"],
    password=config["database_connection"]["password"],
    host=config["database_connection"]["host"],
    port="5432"
)

copyprocess("/home/hitachi/uploads",f"{base_path}/archive")

tgz_files = [file for file in os.listdir("/home/hitachi/uploads") if file.endswith('.tgz')]
if len(tgz_files) == 0:
    print('No Job To Process')
    print('*****************On Sleep****************')
    sys.exit(1)
for file in tgz_files:
    file_path = os.path.join("/home/hitachi/uploads", file)
    cutprocessFile(file_path, input_path)
    newfilepath = os.path.join(input_path, file)
    extract_tgz(newfilepath,f"{base_path}/extracted")

    remove_first_line(f"{base_path}/extracted")

    #max_scanid = calculate_max_scanid(f"{base_path}/extracted")

    add_specific_fields(f"{base_path}/extracted", connection)

    csv_files_headers = read_and_clean_csv_headers(f"{base_path}/extracted")

    create_tables(connection, csv_files_headers)

    for filename in os.listdir(f"{base_path}/extracted"):
        if (filename == "AllConf.csv" or os.path.getsize(f"{base_path}/extracted/{filename}") == 0 or not filename.endswith(".csv")):
            continue
        tablename = filename.split('.')[0].lower()
        csv_headers_array = csv_files_headers[tablename]
        bulk2db(connection, schema_name='hitachi',table_name=tablename,data_list=(f"{base_path}/extracted" +'/'+ filename ),csv_columns=csv_headers_array)
        #os.remove(f"{base_path}/extracted" +'/'+ filename)
    #currentTime = current_time()
    #specific_path = f"{file}-{currentTime}"
    #cutprocessFile(input_path,f"{archive_path}/{specific_path}")

connection.close()
