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

class databaseConnection:
    def __init__(self, database_hostname, database_username, database_password, database_dbname):
        self.database_hostname = database_hostname
        self.database_username = database_username
        self.database_password = database_password
        self.database_dbname = database_dbname

    def connect(self):
        try:
            connection = psycopg2.connect(
                host=self.database_hostname,
                database=self.database_dbname,
                user=self.database_username,
                password=self.database_password)
            cursor = connection.cursor()
            return connection, cursor
        except Exception as e:
            print(f"[-] Failed to connect to DB.\n[Err] {e}")
            return False, False

    def fetch_sql(self, sql):
        connection, cursor = self.connect()
        cursor.execute(sql)
        return_results = [item for item in cursor.fetchall()]
        connection.close()

        return return_results

    def execute_sql(self, sql):
        connection, cursor = self.connect()
        cursor.execute(sql)
        connection.commit()
        connection.close()

    def get_column_names(self, schema_name, table_name):
        syntax = f"SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' AND table_schema = '{schema_name}';"
        column_names = self.fetch_sql(syntax)
        return column_names

    def create_new_column(self, schema_name, table_name, column_name, column_type, default_value):
        create_column_syntax = f'ALTER TABLE \"{schema_name}\"."{table_name}" ADD COLUMN "{column_name}" {column_type} DEFAULT \'{default_value}\';'
        self.execute_sql(create_column_syntax)

    def get_max_scanid(self, schema_name, table_name, hostname=False):
        if not hostname:
            query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\" where osfamily='windows';"
        else:
            query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\" where osfamily='windows' and hostname='{hostname}';"

        try:
            return self.fetch_sql(query)[0][0]
        except:
            return 1

    def mark_job(self, job_id, status):
        if not job_id:
            job_id = self.job_id
        update_syntax = f"UPDATE \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" SET status = '{status}'::integer WHERE id = {job_id};"
        self.execute_sql(update_syntax)

    def update_queue_progress(self, job_id, target_length, processed_targets, queue_targets):
        if not job_id:
            job_id = self.job_id
        update_syntax = f"UPDATE \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" SET target_length = '{target_length}'::integer, processed_targets = '{processed_targets}'::integer, queue_targets = '{queue_targets}'::integer, modified_time = '{current_time()}' WHERE id = {job_id};"
        self.execute_sql(update_syntax)

    def pick_job(self, filter_tablename=False):
        self.inventory_jobs_schema = config["inventory_database_information"]["inventory_jobs_schema"]
        self.inventory_jobs_tablename = config["inventory_database_information"]["inventory_jobs_tablename"]
        if filter_tablename:
            fetch_job_sql = f"SELECT id,resourcetypename,ipfieldname,credentialfieldname,query,conditions,tablename,status,createdtime,threads,jobtype,hostnamefieldname FROM \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" Where status=0 and tablename!='product' and jobtype='inventory' and tablename='{filter_tablename}' order by priority desc Limit 1;"
        else:
            fetch_job_sql = f"SELECT id,resourcetypename,ipfieldname,credentialfieldname,query,conditions,tablename,status,createdtime,threads,jobtype,hostnamefieldname FROM \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" Where status=0 and tablename!='product' and jobtype='inventory' order by priority desc Limit 1;"

        try:
            job_result = self.fetch_sql(fetch_job_sql)[0]
            self.job_id = job_result[0]
        except Exception as e:
            return False

        job_data = {
            "job_id": self.job_id,
            "resourcetype_name": job_result[1],
            "ip_field_name": job_result[2],
            "credential_field_name": job_result[3],
            "query": job_result[4],
            "conditions": job_result[5],
            "tablename": job_result[6],
            "status": job_result[7],
            "createdtime": job_result[8],
            "threads": job_result[9],
            "jobtype": job_result[10],
            "hostnamefieldname": job_result[11],
        }
        self.mark_job(self.job_id, 2)
        return job_data

    def bulk2db(self, schema_name, table_name, data_list):
        conn, cursor = self.connect()
        input_file_handle = open(data_list, "r", encoding="utf-8", errors="ignore")
        cursor.copy_expert(f"copy \"{schema_name}\".\"{table_name}\" from STDIN CSV HEADER QUOTE '\"'", input_file_handle)
        conn.commit()
        conn.close()

    def check_for_wmi_error(self, target_data, job_data):
        conn, cursor = self.connect()
        error_table = {
            "RPC server is unavailable": "'Error 0x800706ba' or 'RPC server is unavailable'",
            "0x800706ba": "'Error 0x800706ba' or 'RPC server is unavailable'",
            "0x80041032": '"5858" and "Result Code 0x80041032"',
            "WBEM_E_NOT_FOUND": '"Error 0x80041002 (WBEM_E_NOT_FOUND)"',
            "0x80041002 ": '"Error 0x80041002 (WBEM_E_NOT_FOUND)"',
            "No such interface supported": 'No such interface supported',
            "Access denied": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
            "Access is denied": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
            "0x80070005": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
            "0x80041003": '"Error 0x80041003", "Error 0x80070005" or "Access denied"',
            "Fatal Error During Installation": '"Error 1603" or "Fatal Error During Installation"',
            "Error 1603": '"Error 1603" or "Fatal Error During Installation"',
            "Timeout Error": '"Timeout Error"',
            "Connection could not be established": '"Failure to Connect" or "Connection could not be established"',
            "Failure to Connect": '"Failure to Connect" or "Connection could not be established"',
            "Generic failure": 'get-WmiObject: "Generic Failure"',
            "Key not valid for use in specified state": 'Specified credential is not valid for current user.'
        }
        error_message = target_data["command_error"]
        if len(error_message) >= 4:
            for error, error_detail in error_table.items():
                if error.lower() in error_message.lower():
                    query = "Insert into inventory_errors.error_results (schemaname, tablename, errorcode, ipaddress, reason, functionname, errortime, recordid, message, hostname, jobtype) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                    values = ("wmi_inventory",
                              job_data["tablename"],
                              "5007",
                              target_data["ipaddress_string"],
                              error_detail,
                              "ExecuteJobs", current_time(), str(target_data.get("id", "N/A")), error,
                        target_data.get("hostname", "N/A"),
                        "deviceInventory")
                    try:
                        cursor.execute(query, values)
                        conn.commit()
                        conn.close()
                        return True
                    except Exception as e:
                        print(f"[-] Failed to report WMI error.\n[Err] {e}")
                        conn.close()


def insert_to_db(output_filename, config_file):
    conn, cursor = connect_to_db(config_file["database_hostname"], config_file["database_username"], config_file["database_password"], config_file["database_db_name"])
    input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
    cursor.copy_expert("copy network_node_discovery.arp_table from STDIN CSV HEADER QUOTE '\"'", input_file_handle)
    conn.commit()
    conn.close()

def insert_csv_to_db(output_filename, schema_name, table_name, config_file):
    conn, cursor = connect_to_db(config_file["database_hostname"], config_file["database_username"], config_file["database_password"], config_file["database_db_name"])
    input_file_handle = open(output_filename, "r", encoding="utf-8", errors="ignore")
    cursor.copy_expert(f"copy {schema_name}.{table_name} from STDIN with delimiter ';' CSV header quote '`'", input_file_handle)
    conn.commit()
    conn.close()
