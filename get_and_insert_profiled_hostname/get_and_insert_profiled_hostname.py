import  psycopg2
import  json

config = open(rf"./appsettings.json", "r", encoding="utf-8", errors="ignore")
config = json.load(config)

def db_connection():
    try:
        conn = psycopg2.connect(
                                    host=config["db_host"],
                                    port=config["db_port"],
                                    database=config["db_name"],
                                    user=config["db_username"],
                                    password=config["db_password"]
                               )
        ps_cursor = conn.cursor()
        return conn, ps_cursor        
    except Exception as e:
        print(f"[-] Failed To Connect To Database.\n\t[Err] {e}")
        
def get_all_tables_names():    
    try:
        conn, cur = db_connection()
        cur.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'inventory_history' ;")
        all_tables_names= cur.fetchall()
        cur.execute(""" select c.relname as tablename
                        from pg_class c
                        join pg_namespace n on n.oid = c.relnamespace
                        where c.relkind = 'r'
                                    and n.nspname not in ('information_schema','pg_catalog')
                                    and c.reltuples <= 0
                                    AND	n.nspname = 'inventory_history';""")
        all_empty_tables= cur.fetchall()
        #print(type(all_empty_tables),type(all_tables_names))
        not_empty_tables = set(all_tables_names) - set(all_empty_tables)
        print("[+] Tables Names Got Successfully.\n")
        return not_empty_tables
    except Exception as e:
        print(f"[-] Failed To Get Data From Database.\n\t[Err] {e}")      
    finally:
        if conn:
            conn.close()
            
def update_profiled_data():
    try:
        all_tables_names = get_all_tables_names()
        conn, cur = db_connection()
        for table_name in all_tables_names:       
            table_name = list(table_name)
            table_name = table_name.pop(0)
            cur.execute(f"SELECT hostname,fullscan_history FROM inventory_history.{table_name} WHERE fullscan_history > 0 ;")
            print("[*] Updating Profiled Data From Table:" , table_name)
            all_hostnames = cur.fetchall()
            cur.execute(f"DELETE FROM profiled.profiled  WHERE table_name ='{table_name}';")
            conn.commit()
            print("\t[+] Profiled Data Deleted Successfully From Table:" , table_name)
            if  all_hostnames:
                args_str = ','.join(cur.mogrify("(%s,%s,%s)", (x[0],x[1],table_name)).decode('utf-8') for x in all_hostnames)
                cur.execute("INSERT INTO profiled.profiled (hostname , fullscan_history , table_name) VALUES " + args_str + " ON CONFLICT (hostname) DO NOTHING")
                conn.commit()
                print("\t[+] Profiled Data Inserted Successfully From Table:", table_name)
    except Exception as e:
        print(f"[-] Failed To Update Profiled Data in Database.\n\t[Err] {e}")      
    finally:
        if conn:
            conn.close()

update_profiled_data()
