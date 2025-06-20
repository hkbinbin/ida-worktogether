import sqlite3
import socketserver
import threading
import json
import socket
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
    
    def broadcast(self, message, exclude_request:list, self_request):
        with self.lock:
            for conn in self.connections:
                if conn not in exclude_request and conn != self_request:
                    try:
                        conn.sendall(message)
                    except:
                        self.remove_connection(conn)
                
exclude_sockets = []

conn_manager = ConnectionManager()

def send_str_list_toclient(json_list:list[str],client_request: socket.socket):
    client_request.settimeout(5)  # 设置超时时间，单位是秒
    index = 0
    print(json_list) # DEBUG
    
    if not json_list:
        print(client_request.getpeername())
        client_request.sendall("END".encode())
        client_request.settimeout(None)
        print("json is None")
        return
    while index < len(json_list):
        try:
            client_request.sendall(json_list[index].encode())
            client_request.sendall(b'E0@F')
            data = client_request.recv(1024)
            if data.decode().startswith("ACK"):
                index += 1
            else:
                break
        except socket.timeout:
            print(f"Timeout waiting for ACK from client at index {index}")
            break
        except Exception as e:
            print(f"Error: {e}")
            break
    client_request.sendall("END".encode())
    client_request.settimeout(None)
    return

def process_buffer_from_client(data: bytes, client_request):
    data = data.decode()
    data_json = json.loads(data)
    editor = data_json['username']
    clientaction = data_json["clientaction"]
    filename = data_json['filename']
    print("[+] recv a msg type:" + str(clientaction))
    if clientaction == ClientAction.REQUEST_LVAR.value:
        index_ea = data_json["index_ea"]
        column_names, data = db_api.get_all_data_with_ea_action_filter(database_name=filename,table_name="IDA_function",index_ea=index_ea,clientaction=ClientAction.RENAME_LVAR.value)
        # get all info about rename Lvar
        json_list = db_api.get_column_data(column_names,data,"json")
        send_str_list_toclient(json_list,client_request)
    else:
        index_ea = data_json["index_ea"]
        db_api.store_data(database_name=filename,table_name=action_to_table[clientaction],editor=editor,json_data=data,index_ea=index_ea,clientaction=clientaction)
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
            sub = j_data['sub']
            if sub == 1:
                exclude_sockets.append(self.request)
            if auth != PINCODE:
                return
            db_api.initial(filename)
        except Exception as e:
            print(e)
            return
        conn_manager.add_connection(self.request)
        self.request.sendall(b"ACKed")
        try:
            while True:
                data = self.request.recv(1024)
                if not data:
                    break
                print(data)
                process_buffer_from_client(data,self.request)
                conn_manager.broadcast(data, exclude_request=exclude_sockets,self_request=self.request)
        finally:
            conn_manager.remove_connection(self.request)
            try:
                exclude_sockets.remove(self.request)
            except:
                pass
            print(f"client {self.client_address} disconnection")

class MyTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False  # 防止"address already in use"错误

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
