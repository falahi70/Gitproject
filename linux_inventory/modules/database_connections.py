import psycopg2
from .general_functions import *


config = load_config()

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

    def get_max_scanid(self, schema_name, table_name):
        query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\""
        return self.fetch_sql(query)[0][0]

    def get_max_scanid_by_osfamily(self, schema_name, table_name, osfamily):
        query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\" where osfamily = '{osfamily}'"
        scanid = self.fetch_sql(query)[0][0]
        if scanid == None: 
            query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\""
            scanid = self.fetch_sql(query)[0][0]
            if scanid == None: scanid == "1"

        return scanid   #self.fetch_sql(query)[0][0]

    def mark_job(self, job_id, status):
        if not job_id:
            job_id = self.job_id
        update_syntax = f"UPDATE \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" SET status = '{status}'::integer WHERE id = {job_id};"
        self.execute_sql(update_syntax)

    def pick_job(self):
        self.inventory_jobs_schema = config["inventory_database_information"]["inventory_jobs_schema"]
        self.inventory_jobs_tablename = config["inventory_database_information"]["inventory_jobs_tablename"]
        fetch_job_sql = f"SELECT id,resourcetypename,ipfieldname,credentialfieldname,query,conditions,tablename,status,createdtime,threads,jobtype,hostnamefieldname FROM \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" Where status=0 and jobtype='inventory' order by priority desc Limit 1;"

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



