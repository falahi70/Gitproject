import psycopg2
import json
import getpass
import datetime


try:
    current_user = str(getpass.getuser()).split("\\")[-1]
    config_path = rf"/CoreInspect/agents/snmpAgent"
    config = open(rf"{config_path}/appsettings.json", "r", encoding="utf-8", errors="ignore")
    config = json.load(config)
except Exception as e:
    print(f"[-] Failed To Read Config File.\n\t[Err] {e}")

def current_time():
    c_time = str(datetime.datetime.now())
    return c_time[:19]

def dbconnect():
    conn = psycopg2.connect(
        host=config["databaseHost"],
        database=config["databaseName"],
        user=config["databaseUsername"],
        password=config["databasePassword"])

    ps_cursor = conn.cursor()
    return conn, ps_cursor

def executeDBSyntax(syntax):
    conn, curser = dbconnect()
    curser.execute(syntax)
    conn.commit()

def insertDB(columns, values):
    conn, cursor = dbconnect()
    cursor.execute(columns, values)
    conn.commit()

def insert_csv_to_db(output_filename):
    conn, cursor = dbconnect()
    input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
    cursor.copy_expert("copy network_node_discovery.arp_table from STDIN CSV HEADER QUOTE '\"'", input_file_handle)
    conn.commit()
    conn.close()

def retention(scanid, schema_name, table_name):
    db_syntax = f"Delete From \"{schema_name}\".\"{table_name}\" Where scanid <= {scanid-5}"
    executeDBSyntax(db_syntax)

def get_credential(credential_name):
    conn, curser = dbconnect()
    total_syntax = f"SELECT \"username\", \"string\" FROM {config['mainSchemaName']}.clixml Where \"name\"='{credential_name}';"
    try:
        curser.execute(total_syntax)
    except Exception as e:
        print(f"[-] Error: {e}")
    data = curser.fetchall()
    username = data[0][0]
    password = data[0][1]
    return username, password


def get_schema_list():
    conn, curser = dbconnect()
    total_syntax = f"SELECT schema_name FROM information_schema.schemata;"
    try:
        curser.execute(total_syntax)
    except Exception as e:
        print(f"[-] Error: {e}")
    data = curser.fetchall()
    schema_list = []
    for row in data:
        schema_list.append(row[0])

    return schema_list

def create_new_schema(schema_name):
    syntax = f"CREATE SCHEMA {schema_name};"
    try:
        executeDBSyntax(syntax)
        return 0
    except Exception as e:
        print(f"[-] Error: {e}")
        return -1

def get_tablename_list(schema_name):
    conn, curser = dbconnect()
    syntax = f"SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = '{schema_name}'"
    try:
        curser.execute(syntax)
    except Exception as e:
        print(f"[-] Error: {e}")
    data = curser.fetchall()
    table_list = []
    for row in data:
        table_list.append(row[0])

    return table_list

def create_new_table(schemaname, tablename):
    drop_sequence_syntax = f'DROP SEQUENCE IF EXISTS "{schemaname}"."{tablename}_seq";'
    create_sequence_syntax = f'CREATE SEQUENCE "{schemaname}"."{tablename}_seq" INCREMENT 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1;'
    create_table_syntax = f'CREATE TABLE "{schemaname}"."{tablename}" ("id" int4 NOT NULL, "hostname" varchar(255) DEFAULT \'-\', "scanid" int8 DEFAULT 1, "scannedip" int8 DEFAULT 0, "command" varchar(255) DEFAULT \'-\', "parser" varchar(255) DEFAULT \'-\', "createdtime" varchar(50) DEFAULT \'1999-01-01 00:00:00\', PRIMARY KEY ("id"));'
    add_sequence_syntax = f'ALTER TABLE "{schemaname}"."{tablename}" ALTER COLUMN id SET DEFAULT nextval(\'{schemaname}.{tablename}_seq\');'
    try:
        executeDBSyntax(drop_sequence_syntax)
        executeDBSyntax(create_sequence_syntax)
        executeDBSyntax(create_table_syntax)
        executeDBSyntax(add_sequence_syntax)
        return 0
    except Exception as e:
        print(f"[-] Error: {e}")
        return -1

def get_columnname_list(schemaname, tablename):
    conn, curser = dbconnect()
    syntax = f"SELECT column_name FROM information_schema.columns WHERE table_schema = '{schemaname}' AND table_name = '{tablename}';"
    try:
        curser.execute(syntax)
    except Exception as e:
        print(f"[-] Error: {e}")
    data = curser.fetchall()
    column_list = []
    for row in data:
        column_list.append(row[0])

    return column_list

def create_new_column(schemaname, tablename, columnname):
    syntax = f'ALTER TABLE "{schemaname}"."{tablename}" ADD COLUMN "{columnname}" varchar(500) DEFAULT \'-\';'
    executeDBSyntax(syntax)

def insert_dictionary_data(schemaname, tablename, data):
    conn, cursor = dbconnect()
    # {"name": "Reza", "Family":"Sarvani"}
    column_list = '","'.join(data.keys())
    column_list = f'"{column_list}"'
    value_list = "%s," * len(list(data.values()))
    value_list = value_list[:-1]
    try:
        syntax = f'Insert Into {schemaname}."{tablename}" ({column_list}) VALUES ({value_list})'
        cursor.execute(syntax, list(data.values()))
        conn.commit()
        print("[+] Data Inserted Into Database.")
    except Exception as e:
        print("[-] Failed To Insert into Database")
        return -1

def get_scan_id(schemaname, tablename, hostname):
    conn, cursor = dbconnect()
    # columnname = tablename.lower()
    # tablename = f"{schemaname}_scan_history"
    # syntax = f'select {columnname} from inventory_history."{tablename}" where hostname=\'{hostname}\''
    syntax = f'select MAX(scanid) from "{schemaname}"."{tablename}" where hostname=\'{hostname}\''
    try:
        cursor.execute(syntax)
        data = cursor.fetchall()
        scanid = int(data[0][0]) + 1
    except Exception as e:
        scanid = 1

    return scanid
