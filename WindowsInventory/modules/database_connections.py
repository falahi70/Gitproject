import psycopg2
from .general_functions import *
import os

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
        try:
            return_results = [item for item in cursor.fetchall()]
        except Exception as e:
            return_results = []
        connection.close()

        return return_results

    def execute_sql(self, sql):
        connection, cursor = self.connect()
        cursor.execute(sql)
        connection.commit()
        connection.close()

    def bulk2db(self, schema_name, table_name, data_list,csv_columns):
        conn, cursor = self.connect()
        with open(data_list, "rb",) as input_file_handle:
            print(f"{data_list}")
            copy_sql = f"COPY \"{schema_name}\".\"{table_name}\" ({', '.join(csv_columns)}) FROM STDIN WITH CSV HEADER;"
            cursor.copy_expert(copy_sql, input_file_handle)
        conn.commit()
        conn.close()


    def get_column_names(self, schema_name, table_name):
        syntax = f"SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' AND table_schema = '{schema_name}';"
        column_names = self.fetch_sql(syntax)
        return column_names

    def create_new_column(self, schema_name, table_name, column_name, column_type, default_value):
        create_column_syntax = f'ALTER TABLE \"{schema_name}\"."{table_name}" ADD COLUMN "{column_name}" {column_type} DEFAULT \'{default_value}\';'
        self.execute_sql(create_column_syntax)

    def get_max_scanid(self, schema_name, table_name, hostname=False):
        if hostname:
            query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\" where hostname='{hostname}';"
        else:
            query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\" where osfamily='windows';"
        return self.fetch_sql(query)[0][0]

    def json_update(self, schema_name, table_name, json_data, is_list=False):
        if is_list:
            conn, cursor = self.connect()
            for data in json_data:
                statement_sql = f"update \"{schema_name}\".\"{table_name}\" set $update_statement$ where id='$data_id$'"
                data_id = str(data["id"])
                statement_sql = statement_sql.replace("$data_id$", data_id)
                del data["id"]

                for key, value in data.items():
                    value = str(value).replace("'", "''")
                    statement_sql = statement_sql.replace("$update_statement$",
                                                          f"\"{key}\"='{value}',$update_statement$")
                statement_sql = statement_sql.replace(",$update_statement$", "")

                cursor.execute(statement_sql)
            try:
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[-] Error commiting data into DB.\n[Err] {e}")
                return False

        else:
            statement_sql = f"update \"{schema_name}\".\"{table_name}\" set $update_statement$ where id='$data_id$'"
            data_id = str(json_data["id"])
            statement_sql = statement_sql.replace("$data_id$", data_id)
            del json_data["id"]

            for key, value in json_data.items():
                value = str(value).replace("'", "''")
                statement_sql = statement_sql.replace("$update_statement$", f"\"{key}\"='{value}',$update_statement$")
            statement_sql = statement_sql.replace(",$update_statement$", "")
            # print(f"[!] statement_sql: {statement_sql}")

            if self.execute_sql(statement_sql):
                return True
            return False

    def json2db(self, schema_name, table_name, json_data_list, id_included=True):
        connection, cursor = self.connect()

        column_names = self.get_column_names(schema_name, table_name)
        column_names = [column_name[0] for column_name in column_names]
        # [id, subdomain, domain, created_time, ...]

        # print(f"[!] json_data_list: {json_data_list}")
        for data in json_data_list:
            insert_query = f"Insert Into \"{schema_name}\".\"{table_name}\" ($cn$) VALUES($vl$) On CONFLICT DO NOTHING"
            for column in column_names:
                if not id_included and str(column).lower() == "id":
                    continue
                value = data.get(column, 'N/A')
                value = str(value).replace("'", "''")
                value = str(value).replace(",", ";")
                insert_query = insert_query.replace("$cn$", f"\"{column}\",$cn$")
                insert_query = insert_query.replace("$vl$", f"'{value}',$vl$")
            insert_query = insert_query.replace(",$cn$", "")
            insert_query = insert_query.replace(",$vl$", "")
            # print(f"[!] Insert Query: {insert_query}")
            cursor.execute(insert_query)
        connection.commit()
        connection.close()

    def json2bulkdb(self, schema_name, table_name, json_data_list, lower_keys=True):
        connection, cursor = self.connect()

        column_names = self.get_column_names(schema_name, table_name)
        column_names = [column_name[0] for column_name in column_names]
        # [id, subdomain, domain, created_time, ...]

        headers_row = ",".join(column_names)
        output_filename = f"{generate_new_GUID()}_{table_name}_bulk.csv"
        output_file_handle = open(output_filename, "w", encoding="utf-8", errors="replace")
        output_file_handle.write(f"{headers_row}\n")

        for data in json_data_list:
            if lower_keys:
                data = {k.lower(): v for k, v in data.items()}
            write_str = ""
            for column in column_names:
                value = data.get(str(column).lower(), "N/A")
                value = str(value).strip()
                value = str(value).replace('\x00','')
                value = value.replace("\n", "")
                value = str(value).replace("'", "''")
                value = str(value).replace(",", ";")
                if len(value) < 1:
                    value = "N/A"
                write_str += f"{value},"
            write_str = write_str[:-1]
            output_file_handle.write(f"{write_str}\n")

        output_file_handle.close()


        try:
            self.bulk2db(schema_name, table_name, output_filename)
            os.remove(output_filename)
            return 1
        except Exception as e:
            print(f"[-] Failed to remove [{output_filename}]\n[Err] {e}")
            return 0

        # # print(f"[!] json_data_list: {json_data_list}")
        # for data in json_data_list:
        #     insert_query = f"Insert Into \"{schema_name}\".\"{table_name}\" ($cn$) VALUES($vl$) On CONFLICT DO NOTHING"
        #     for column in column_names:
        #         value = data.get(column, 'N/A')
        #         value = str(value).replace("'", "''")
        #         value = str(value).replace(",", ";")
        #         insert_query = insert_query.replace("$cn$", f"\"{column}\",$cn$")
        #         insert_query = insert_query.replace("$vl$", f"'{value}',$vl$")
        #     insert_query = insert_query.replace(",$cn$", "")
        #     insert_query = insert_query.replace(",$vl$", "")
        #     # print(f"[!] Insert Query: {insert_query}")
        #     cursor.execute(insert_query)
        # connection.commit()
        # connection.close()

    def mark_job(self, job_id, status):
        if not job_id:
            job_id = self.job_id
        update_syntax = f"UPDATE \"server_management\".\"queue\" SET status = '{status}'::integer WHERE id = {job_id};"
        self.execute_sql(update_syntax)

    def pick_job(self, hostname, inventory_endpoint=False):
        if inventory_endpoint:
            fetch_job_sql = f"SELECT id,hostname,job,queue_status,db_status,inventory_status,filename,created_time,finished_time FROM \"server_management\".\"queue\" Where queue_status='1' and inventory_status='0' and hostname='{hostname}' Limit 1;"
        else:
            fetch_job_sql = f"SELECT id,hostname,job,queue_status,db_status,inventory_status,filename,created_time,finished_time FROM \"server_management\".\"queue\" Where queue_status='0' and hostname='{hostname}' Limit 1;"
        try:
            job_result = self.fetch_sql(fetch_job_sql)[0]
            self.job_id = job_result[0]
        except Exception as e:
            return []

        job_data = {
            "id": self.job_id,
            "hostname": job_result[1],
            "job": job_result[2],
            "queue_status": job_result[3],
            "db_status": job_result[4],
            "inventory_status": job_result[5],
            "filename": job_result[6],
            "created_time": job_result[7],
            "finished_time": job_result[8]
        }

        return job_data

    def pick_db_job(self):
        fetch_job_sql = f"SELECT id,hostname,job,queue_status,db_status,inventory_status,filename,created_time,finished_time FROM \"server_management\".\"queue\" Where queue_status='1' and inventory_status='1' and db_status='0' Limit 1;"

        try:
            job_result = self.fetch_sql(fetch_job_sql)[0]
            self.job_id = job_result[0]
        except Exception as e:
            return []

        job_data = {
            "id": self.job_id,
            "hostname": job_result[1],
            "job": job_result[2],
            "queue_status": job_result[3],
            "db_status": job_result[4],
            "inventory_status": job_result[5],
            "filename": job_result[6],
            "created_time": job_result[7],
            "finished_time": job_result[8]
        }

        return job_data

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



