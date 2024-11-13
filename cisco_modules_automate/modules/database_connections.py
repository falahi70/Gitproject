import datetime
import subprocess
import ipaddress
import urllib.parse
import re
import json
import requests
import time
import psycopg2
from glob import glob
import os
from pathlib import Path
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
        column_names = [column[0] for column in column_names]
        return column_names

    def create_new_column(self, schema_name, table_name, column_name, column_type, default_value):
        create_column_syntax = f'ALTER TABLE \"{schema_name}\"."{table_name}" ADD COLUMN "{column_name}" {column_type} DEFAULT \'{default_value}\';'
        self.execute_sql(create_column_syntax)

    def get_max_scanid(self, schema_name, table_name):
        query = f"select MAX(scanid) from \"{schema_name}\".\"{table_name}\""
        return self.fetch_sql(query)[0][0]

    def mark_job(self, job_id, status):
        if not job_id:
            job_id = self.job_id
        update_syntax = f"UPDATE \"{self.inventory_jobs_schema}\".\"{self.inventory_jobs_tablename}\" SET status = '{status}'::integer WHERE id = {job_id};"
        self.execute_sql(update_syntax)

    def pick_wmi_job(self, inventory_jobs_schema, inventory_jobs_tablename):
        self.inventory_jobs_schema = inventory_jobs_schema
        self.inventory_jobs_tablename = inventory_jobs_tablename
        # self.inventory_jobs_schema = config["inventory_database_information"]["inventory_jobs_schema"]
        # self.inventory_jobs_tablename = config["inventory_database_information"]["inventory_jobs_tablename"]
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

    def list2db(self, insert_db_datas, target_schema, target_table, key_column, update_statement=False):
        target_db_columns = self.get_column_names(target_schema, target_table)
        header_row = ",".join(target_db_columns)

        tmp_directory = os.getenv("tmp")
        output_filename = f"{tmp_directory}\{generate_new_GUID()}_bulk.csv"
        output_file_handle = open(output_filename, "w", encoding="utf-8", errors="ignore")
        output_file_handle.write(f"{header_row}\n")

        for data in insert_db_datas:
            if len(str(data.get(key_column, ""))) < 3 or str(data.get(key_column, "null")) == "null":
                continue
            tmp_row = ""
            for column in target_db_columns:
                # print(f"[!] Column: {column}")
                insert_data = str(data.get(column, "N/A"))
                insert_data = insert_data.replace("\n", "")
                insert_data = insert_data.replace("\r", "")
                insert_data = insert_data.replace("\00", "")
                insert_data = insert_data.replace(",", ";")
                insert_data = insert_data.replace("'", "''")
                insert_data = insert_data.replace('"', "")
                tmp_row += f"{insert_data},"
            tmp_row = tmp_row[:-1]
            output_file_handle.write(f"{tmp_row}\n")
        output_file_handle.close()
        print(f"[+] Output Filename: {output_filename}")

        try:
            os.chmod(output_filename, 0o777)
        except Exception as e:
            print(f"[-] Failed to give permission to output file.\n[Err] {e}")

        create_table_query = f'''drop table if exists {target_schema}.tmp_table CASCADE;

                    CREATE TABLE {target_schema}.tmp_table 
                    AS
                    SELECT * 
                    FROM {target_schema}.{target_table}
                    WITH NO DATA;'''
        self.execute_sql(create_table_query)

        if not update_statement:
            insert_data_query = f'''
                        copy {target_schema}.tmp_table from '{output_filename}' CSV HEADER QUOTE '"';

                        INSERT INTO {target_schema}.{target_table}
                        SELECT DISTINCT ON ({key_column}) *
                        FROM {target_schema}.tmp_table ON Conflict () DO Nothing;
                    '''
        else:
            insert_data_query = f'''
                                copy {target_schema}.tmp_table from '{output_filename}' CSV HEADER QUOTE '"';

                                INSERT INTO {target_schema}.{target_table}
                                SELECT DISTINCT ON ({key_column}) *
                                FROM {target_schema}.tmp_table ON Conflict ({key_column}) DO {update_statement};
                            '''
        self.execute_sql(insert_data_query)

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

    def create_csv(self, headers, data_object, output_filename):
        output_handle = open(output_filename, "w", encoding="utf-8", errors="ignore")
        headers_row = ",".join(headers)
        output_handle.write(f"{headers_row}\n")
        for data in data_object:  # data_object: [{"name":"Reza", "age": 22}, {"name": "John", "age": 22}]
            # data: {"name":"Reza", "age": 22}
            tmp_string = ""
            for header in headers:  # headers: ["name", "age"]
                write_data = data[header].replace(",", "")
                tmp_string += f"{write_data},"
            tmp_string = tmp_string[:-1]
            output_handle.write(f"{tmp_string}\n")


