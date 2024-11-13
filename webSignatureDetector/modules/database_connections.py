import psycopg2

def delete_old_data():
    conn = psycopg2.connect(
        host="192.168.161.33",
        database="CoreInspect",
        user="postgres",
        password="1234rewq!@#$REWQ")
    cursor = conn.cursor()
    cursor.execute(f"delete from webapplication_discovery.\"webapplication_discovery\"")
    conn.commit()

def insert_db(query, values):
    conn = psycopg2.connect(
            host="192.168.161.33",
            database="CoreInspect",
            user="postgres",
            password="1234rewq!@#$REWQ")
    cursor = conn.cursor()
    cursor.execute(query, values)
    conn.commit()
