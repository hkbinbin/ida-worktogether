import ida_nalt
from enum import Enum
import socket
# config list
server_host = "localhost"
server_port = 9999
stop_flag = False  # global stop flag
_server_socket = None

PINCODE = "7a29293b1919e727162fa2362a"
username = "munan"
prefix = "Th1S_Fu@c_By_Se2er_"
suffix = "_6c436feecb5d3f4a7274ba2081d39_"

# fix arg
filename = "IDA_"+ida_nalt.retrieve_input_file_sha256().hex()[:16]

class ClientAction(Enum):
    RENAME_FUNC = 1
    EDIT_CMT = 2
    RENAME_LVAR = 3