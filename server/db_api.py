import psycopg2
from collections import defaultdict

import psycopg2.sql

# pg_database config
USER = 'postgres'
PASSWORD = '123456'
PG_IP = "localhost"
PG_PORT = 5432

# Server_connect
_pgsql_connection = None

def create_database(database_name:str) -> None:
    global _pgsql_connection
    connection = psycopg2.connect(database = "postgres",user = USER, password =PASSWORD, host=PG_IP, port=PG_PORT)
    _pgsql_connection = connection
    connection.autocommit = True
    cursor = connection.cursor()
    # check if databse exsit
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s",(database_name,))
    exists = cursor.fetchone()

    if not exists:
        cursor.execute(psycopg2.sql.SQL("CREATE DATABASE {}").format(psycopg2.sql.Identifier(database_name)))
    cursor.close()
    connection.close()

def create_table(database_name:str,table_name:str) -> None:
    connection = psycopg2.connect(database = database_name,user = USER, password =PASSWORD, host=PG_IP, port=PG_PORT)
    cursor = connection.cursor()

    query = psycopg2.sql.SQL("""\
        CREATE TABLE IF NOT EXISTS {table}(
            id SERIAL PRIMARY KEY,
            editor VARCHAR(255) NOT NULL,
            binary_data BYTEA NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP    
        );
        """).format(table=psycopg2.sql.Identifier(table_name))
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

def initial(database_name:str) -> None:
    create_database(database_name)
    create_table(database_name,'structure')
    create_table(database_name,'function')

def store_data(database_name:str, table_name:str, editor:str, binary_data:bytes) -> None:
    connection = psycopg2.connect(database = "postgres",user = USER, password =PASSWORD, host=PG_IP, port=PG_PORT)
    cursor = _pgsql_connection.cursor()
    query = psycopg2.sql.SQL("""
        INSERT INTO {table} (editor, binary_data) VALUE (%s, %s)
                             """).format(table=psycopg2.sql.Identifier(table_name))

    cursor.execute(query, (editor, binary_data))
    connection.commit()
    cursor.close()
    connection.close()
