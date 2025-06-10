import sqlite3
import socketserver
import threading

# local_import
import db_api

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

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # 处理客户端连接
        print(f"客户端 {self.client_address} 已连接")
        conn_manager.add_connection(self.request)
        try:
            while True:
                data = self.request.recv(1024)
                if not data:
                    break
                print(f"收到来自 {self.client_address} 的数据: {data}")
                # 广播给所有其他客户端
                conn_manager.broadcast(data, exclude_request=self.request)
                # 回传数据给发送者
                # self.request.sendall(b"Server: Message received and broadcasted")
        finally:
            conn_manager.remove_connection(self.request)
            print(f"客户端 {self.client_address} 已断开")

class MyTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True  # 防止"address already in use"错误

if __name__ == "__main__":
<<<<<<< HEAD
    db_api.initial("Testing")
    exit(1)
=======
    conn = init_database()

>>>>>>> eee8195ce3345a74f50c6c7c643e0336ec1ce5b4
    HOST, PORT = "0.0.0.0", 9999
    with MyTCPServer((HOST, PORT), MyTCPHandler) as server:
        print(f"服务器启动，监听 {HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n正在关闭服务器...")
            server.shutdown()
            server.server_close()
            print("服务器已关闭")
