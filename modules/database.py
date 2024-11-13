import psycopg2
from modules.general_function import *


def create_tables(connection, schema):
    with connection.cursor() as cursor:
        for table_name, columns in schema.items():
            columns_sql = ", ".join([f"{column} TEXT" for column in columns])
            create_table_query = f"CREATE TABLE IF NOT EXISTS hitachi.{table_name} ({columns_sql});"
            cursor.execute(create_table_query)
            print(f"Table '{table_name}' created successfully.")

    connection.commit()

def create_tables(connection, schema):
    int_fields = {"scanid", "scannedip"}
    auto_increment_field = "id"
    
    with connection.cursor() as cursor:
        for table_name, columns in schema.items():
            columns_sql = [f"id BIGSERIAL PRIMARY KEY"]
            
            for column in columns:
                if column in int_fields:
                    columns_sql.append(f"{column} INT8")
                else:
                    columns_sql.append(f"{column} TEXT")
            
            create_table_query = f"CREATE TABLE IF NOT EXISTS hitachi.{table_name} ({', '.join(columns_sql)});"
            cursor.execute(create_table_query)
            print(f"Table '{table_name}' created successfully.")

    connection.commit()

def bulk2db(connection, schema_name, table_name, data_list, csv_columns):
    with connection.cursor() as cursor:
        table_column_name_query = f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name}'"
        cursor.execute(table_column_name_query)
        return_results = cursor.fetchall()
        table_columns = [row[0] for row in return_results]
        #remove_non_matching_columns(data_list, table_columns)
        csv_headers_array = csv_columns

        if not all(col in table_columns for col in csv_headers_array):
            raise ValueError("there are non matching columns in csv file")

        with open(data_list, "rb") as input_file_handle:
            copy_sql = f"COPY \"{schema_name}\".\"{table_name}\" ({', '.join(csv_headers_array)}) FROM STDIN WITH CSV HEADER;"
            cursor.copy_expert(copy_sql, input_file_handle)

        connection.commit()

def get_max_scanidnohost(connection, schema_name, table_name):
    try:
        with connection.cursor() as cursor:
            query = f"SELECT MAX(scanid) FROM \"{schema_name}\".\"{table_name}\";"
            cursor.execute(query)
            result = cursor.fetchone()

            return result[0] if result[0] is not None else 0

    except psycopg2.errors.UndefinedTable:
        connection.rollback()
        return 0
