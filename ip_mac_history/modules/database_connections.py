import psycopg2


def connect_to_db(database_hostname, database_username, database_password, database_db_name):
    ip_address = database_hostname
    database_name = database_db_name
    port = "5432"
    username = database_username
    password = database_password
    conn = psycopg2.connect(
        host=ip_address,
        port=port,
        database=database_name,
        user=username,
        password=password)
    ps_cursor = conn.cursor()
    return conn, ps_cursor


def insert_to_db(output_filename, config_file):
    conn, cursor = connect_to_db(config_file["database_hostname"], config_file["database_username"], config_file["database_password"], config_file["database_db_name"])
    input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
    cursor.copy_expert("copy network_node_discovery.arp_table from STDIN CSV HEADER QUOTE '\"'", input_file_handle)
    conn.commit()
    conn.close()

def insert_csv_to_db(output_filename, schema_name, table_name, config_file):
    conn, cursor = connect_to_db(config_file["database_hostname"], config_file["database_username"], config_file["database_password"], config_file["database_db_name"])
    input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
    cursor.copy_expert(f"copy {schema_name}.{table_name} from STDIN CSV HEADER QUOTE '\"'", input_file_handle)
    conn.commit()
    conn.close()