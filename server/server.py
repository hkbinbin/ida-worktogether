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
                if conn != exclude_request:
                    try:
                        conn.sendall(message)
                    except:
                        # 连接可能已关闭
                        self.remove_connection(conn)
                

conn_manager = ConnectionManager()



class ClientAction(Enum):
    RENAME_FUNC = 1
    EDIT_CMT = 2

def process_buffer_from_client(data: bytes):
    data = data.decode()
    data_json = json.loads(data)
    editor = data_json['username']
    clientaction = data_json["clientaction"]
    filename = data_json['filename']
    db_api.store_data(database_name=filename,table_name=action_to_table[clientaction],editor=editor,json_data=data)
    return

action_to_table = dict()
action_to_table[ClientAction.RENAME_FUNC.value] = "IDA_function"
action_to_table[ClientAction.EDIT_CMT.value] = "IDA_comment"

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # 处理客户端连接
        print(f"客户端 {self.client_address} 已连接")
        # 确认握手信息
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
                # 处理数据
                process_buffer_from_client(data)
                # 广播给其他客户端
                conn_manager.broadcast(data, exclude_request=self.request)
        finally:
            conn_manager.remove_connection(self.request)
            print(f"客户端 {self.client_address} 已断开")

class MyTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True  # 防止"address already in use"错误

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9999
    try_connect = db_api.get_connection("postgres")
    if try_connect is None:
        print(f"连接数据库失败")
        exit(0)
    with MyTCPServer((HOST, PORT), MyTCPHandler) as server:
        print(f"服务器启动，监听 {HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n正在关闭服务器...")
            server.shutdown()
            server.server_close()
            print("服务器已关闭")
