import psycopg2
import sys


class Database:
    def __init__(self, hostname, port, username, password, db_name):
        self.db_hostname = hostname
        self.db_port = port
        self.db_username = username
        self.db_password = password
        self.db_name = db_name

    def connect(self):
        try:
            db_connection = psycopg2.connect(
                host=self.db_hostname,
                database=self.db_name,
                user=self.db_username,
                password=self.db_password)
            db_cursor = db_connection.cursor()
            return db_connection, db_cursor
        except Exception as e:
            print(f"Error Connecting To DB: {e}")
            return False

    def execute_query(self, query):
        db_connection, db_cursor = self.connect()
        db_cursor.execute(query)
        db_connection.commit()
        db_connection.close()

    def get_query_result(self, query, single_column=True):
        # if "information_schema" not in query:
        #     print(f"[!] Query: {query}")
        db_connection, db_cursor = self.connect()
        db_cursor.execute(query)
        return_data = []

        for item in db_cursor.fetchall():
            # if "information_schema" not in query:
            #     print(f"DB Result: {item}")
            if single_column:
                return_data.append(item[0])
            else:
                return_data.append(item)

        db_connection.close()
        return return_data

    def get_schema_name(self):
        query = r'SELECT schema_name FROM information_schema.schemata'
        schema_names = self.get_query_result(query)
        return schema_names

    def get_table_name(self, schema_name):
        query = f"SELECT table_name FROM information_schema.columns WHERE table_schema = '{schema_name}' Group By table_name;"
        table_names = self.get_query_result(query)
        return table_names

    def get_column_name(self, schema_name, table_name):
        query = f"SELECT column_name FROM information_schema.columns WHERE table_schema = '{schema_name}' AND table_name = '{table_name}';"
        column_names = self.get_query_result(query)
        return column_names

    def is_table_exists(self, schema_name, table_name):
        query = f"SELECT table_name, count(table_name) FROM information_schema.columns WHERE table_schema = '{schema_name}' and table_name = '{table_name}' Group By table_name;"
        try:
            table_exist_result = self.get_query_result(query)[0]
            if table_exist_result:
                return True
            return False
        except Exception as e:
            # print(f"[-] Failed to check table existence.\n[Err] {e}")
            return False

    def is_column_exists(self, schema_name, table_name, column_name):
        query = f"SELECT count(column_name) FROM information_schema.columns WHERE table_schema = '{schema_name}' AND table_name   = '{table_name}' And \"column_name\" = '{column_name}';"
        column_exist_result = self.get_query_result(query)[0]
        if int(column_exist_result) > 0:
            return True
        return False

    def create_default_table(self, schema_name, table_name):
        # Creating table
        create_table_query = f'CREATE TABLE "{schema_name}"."{table_name}" ("id" varchar(200) NOT NULL,  "hostname" varchar(255) DEFAULT \'-\', "fullscan_history" int4 DEFAULT 0, "updatedtime" varchar(25), PRIMARY KEY ("id"));'

        # # Adding the sequence to id column
        # create_sequence_query = f"""CREATE SEQUENCE {table_name}_history_seq OWNED BY \"{schema_name}\".\"{table_name}\".id;
        # ALTER TABLE \"{schema_name}\".\"{table_name}\" ALTER COLUMN id SET DEFAULT nextval('{table_name}_history_seq');
        # UPDATE \"{schema_name}\".\"{table_name}\" SET id = nextval('{table_name}_history_seq');"""

        try:
            self.execute_query(create_table_query)
            # self.execute_query(create_sequence_query)
        except Exception as e:
            print(f"[-] Error while creating table.\n[Err] {e}")
            return False

    def add_column(self, schema_name, table_name, column_name, column_type="varchar", default="0"):
        if "int" in column_type.lower():
            query = f'ALTER TABLE \"{schema_name}\".\"{table_name}\" ADD COLUMN IF NOT EXISTS "{column_name}" {column_type} DEFAULT {default};'
        else:
            query = f'ALTER TABLE \"{schema_name}\".\"{table_name}\" ADD COLUMN IF NOT EXISTS "{column_name}" {column_type}(5000) DEFAULT \'{default}\';'
        try:
            self.execute_query(query)
            return True
        except Exception as e:
            print(f"[-] Error while creating new column.\n[Err] {e}")
            return False

    def bulk2db(self, schema_name, table_name, csv_filename):
        conn, cursor = self.connect()
        input_file_handle = open(csv_filename, "r", encoding="utf-8", errors="ignore")
        cursor.copy_expert(
            f"copy \"{schema_name}\".\"{table_name}\" from STDIN CSV HEADER QUOTE '\"'",
            input_file_handle)
        conn.commit()
        conn.close()

    def get_osfamily(self, schema_name, table_name, hostname):
        query = f'select osfamily from "{schema_name}"."{table_name}" where hostname=\'{hostname}\';'
        try:
            osfamily_result = self.get_query_result(query)
            return osfamily_result
        except Exception as e:
            return False

