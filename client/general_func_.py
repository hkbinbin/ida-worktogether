import socket
from config_ import *
import json
def sub_connect_server():
    sub_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sub_socket.connect((server_host,server_port))
    data = {
        "auth" : PINCODE,
        'filename' : filename,
        'sub' : 1,
    }
    j_data = json.dumps(data)
    sub_socket.sendall(j_data.encode())
    data = sub_socket.recv(24)
    if data.startswith(b"ACKed"):
        return sub_socket
    else:
        return None # TODO erro handler