import psycopg2
from collections import defaultdict

import psycopg2.sql
from config_ import *


# Server_connect
_pgsql_connection = None
_current_database = None

def get_connection(database_name):
    global _pgsql_connection
    global _current_database
    if _pgsql_connection is None or _pgsql_connection.closed or _current_database != database_name:
        try:
            connection = psycopg2.connect(database = database_name,user = USER, password =PASSWORD, host=PG_IP, port=PG_PORT)
        except psycopg2.OperationalError as e:
            _pgsql_connection = None
            return None
        _pgsql_connection = connection
        _current_database = database_name
    else:
        connection = _pgsql_connection
    return connection


def create_database(database_name:str) -> bool:
    connection = get_connection("postgres")
    connection.autocommit = True
    cursor = connection.cursor()
    # check if databse exsit
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s",(database_name,))
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(psycopg2.sql.SQL("CREATE DATABASE {}").format(psycopg2.sql.Identifier(database_name)))
        return True
    cursor.close()
    return False

def create_table(database_name, table_name):
    """Create a table safely in the specified database."""
    connection = get_connection(database_name)
    cursor = connection.cursor()

    # Use psycopg2.sql to safely inject identifiers (like table names)
    query = psycopg2.sql.SQL("""
        CREATE TABLE IF NOT EXISTS {table} (
            id SERIAL PRIMARY KEY,
            index_ea BIGINT DEFAULT -1,
            editor VARCHAR(255) NOT NULL,
            clientaction INT DEFAULT -1,
            json TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """).format(table=psycopg2.sql.Identifier(table_name))
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

def initial(database_name:str) -> None:
    create_database(database_name)
    create_table(database_name,'IDA_function')
    create_table(database_name,'IDA_structure')
    create_table(database_name,'IDA_comment')

def store_data(database_name:str, table_name:str, editor:str, json_data:str, index_ea:int, clientaction:int) -> None:
    connection = get_connection(database_name)
    cursor = _pgsql_connection.cursor()
    query = psycopg2.sql.SQL("""
        INSERT INTO {table} (editor, json, index_ea, clientaction) VALUES (%s, %s, %s, %s)""").format(table=psycopg2.sql.Identifier(table_name))
    cursor.execute(query, (editor, json_data, index_ea, clientaction))
    connection.commit()
    cursor.close()
    connection.close()

def get_all_data_with_ea_action_filter(database_name, table_name, index_ea, clientaction):
    """Retrieve all data and column names from a table in the specified database."""
    try:
        connection = get_connection(database_name)
        cursor = connection.cursor()
        query = psycopg2.sql.SQL("""
            SELECT * FROM {table} WHERE index_ea = %s AND clientaction = %s;
        """).format(table=psycopg2.sql.Identifier(table_name))
        cursor.execute(query, (index_ea, clientaction))
        data = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        cursor.close()
        connection.close()
        return column_names, data
    except Exception as e:
        print(f"An error occurred: {e}")
        connection.close()
        return None, None

def get_column_data(column_names, data, column_name):
    """从查询结果中提取指定列的数据"""
    if column_names and data:
        if column_name in column_names:
            column_index = column_names.index(column_name)
            column_data = [row[column_index] for row in data]
            return column_data
        else:
            print(f"Column '{column_name}' not found.")
            return None
    else:
        print("No data retrieved.")
        return None
