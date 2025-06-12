import sqlite3
import socketserver
import threading
import json
from enum import Enum
# local_import
import db_api
from config_ import *

class ConnectionManager:
    def __init__(self):
        self.connections = []
        self.lock = threading.Lock()
    
    def add_connection(self, request):
        with self.lock:
            self.connections.append(request)
    
    def remove_connection(self, request):
        with self.lock:
            if request in self.connections:
                self.connections.remove(request)
    
    def broadcast(self, message, exclude_request=None):
        with self.lock:
            for conn in self.connections:
                if True: #conn != exclude_request:
                    try:
                        conn.sendall(message)
                    except:
                        self.remove_connection(conn)
                

conn_manager = ConnectionManager()

def process_buffer_from_client(data: bytes):
    data = data.decode()
    data_json = json.loads(data)
    editor = data_json['username']
    clientaction = data_json["clientaction"]
    print(clientaction)
    filename = data_json['filename']
    db_api.store_data(database_name=filename,table_name=action_to_table[clientaction],editor=editor,json_data=data)
    return

action_to_table = dict()
action_to_table[ClientAction.RENAME_FUNC.value] = "IDA_function"
action_to_table[ClientAction.EDIT_CMT.value] = "IDA_comment"
action_to_table[ClientAction.RENAME_LVAR.value] = "IDA_function"

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"client {self.client_address} connected")
        # handshake
        try:
            data = self.request.recv(1024)
            j_data = json.loads(data.decode())
            auth = j_data['auth']
            filename = j_data['filename']
            if auth != PINCODE:
                return
            db_api.initial(filename)
        except:
            return
        conn_manager.add_connection(self.request)
        try:
            while True:
                data = self.request.recv(1024)
                if not data:
                    break
                process_buffer_from_client(data)
                conn_manager.broadcast(data, exclude_request=self.request)
        finally:
            conn_manager.remove_connection(self.request)
            print(f"client {self.client_address} disconnection")

class MyTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True  # 防止"address already in use"错误

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9999
    try_connect = db_api.get_connection("postgres")
    if try_connect is None:
        print(f"connect database failed")
        exit(0)
    with MyTCPServer((HOST, PORT), MyTCPHandler) as server:
        print(f"server started at: {HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("="*0x10)
            print("Closing...")
            server.shutdown()
            server.server_close()
            print("closed")
