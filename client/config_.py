import ida_nalt
import idc
import os
from enum import Enum
import socket
import queue

# config list
server_host = "172.28.111.106"
server_port = 19999
stop_flag = False  # global stop flag
_server_socket:socket.socket = None

PINCODE = "7a29293b1919e727162fa2362a"
username = "munan"
prefix = "Th1S_Fu@c_By_Se2er_"
suffix = "_6c436feecb5d3f4a7274ba2081d39_"

# fix arg
fullpath = idc.get_input_file_path()
filename_only = os.path.basename(fullpath)
filename = f"IDA_{ida_nalt.retrieve_input_file_sha256().hex()[:16]}_{filename_only}"

# cross mod 
msg_int_flag = False
msg_queue = queue.Queue()
class ClientAction(Enum):
    RENAME_FUNC = 1
    EDIT_CMT = 2
    RENAME_LVAR = 3
    REQUEST_LVAR = 4