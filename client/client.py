import threading
import time
import struct
import socket
import idaapi
import json
import base64
import ida_nalt
import ida_hexrays
import ida_funcs
from enum import Enum

class ClientAction(Enum):
    RENAME_FUNC = 1
    EDIT_CMT = 2

# config list
server_host = "192.168.3.177"
server_port = 9999
stop_flag = False  # 全局终止标志
_server_socket = None

PINCODE = "7a29293b1919e727162fa2362a"
username = "munan"
prefix = "Th1S_Fu@c_By_Se2er_"
suffix = "_6c436feecb5d3f4a7274ba2081d39_"

# fix arg
filename = "IDA_"+ida_nalt.retrieve_input_file_sha256().hex()[:16]

# log_func 
def log_fail(msg):
    print("[-] Fail:",end='')
    print(msg)
def log_success(msg):
    print("[+] success:",end='')
    print(msg)


# proto construction Func

def proto_to_buffer(json_str:str) -> dict:
    json_obj = json.loads(json_str)
    return json_obj

def client_rename_func_buffer(ea, new_name) -> str:
    proto_buffer = proto_header()
    proto_buffer["clientaction"] = ClientAction.RENAME_FUNC.value
    proto_buffer["ea"] = ea
    proto_buffer["new_name"] = new_name
    json_buffer = json.dumps(proto_buffer)
    return json_buffer

def client_edit_comment_buffer(comment_ea:int, cmt:str) -> str:
    proto_buffer = proto_header()
    proto_buffer["clientaction"] = ClientAction.EDIT_CMT.value
    proto_buffer["comment_ea"] = comment_ea
    proto_buffer["cmt"] = cmt
    json_buffer = json.dumps(proto_buffer)
    return json_buffer

# global var used in hooks -> ignore it
_general_prefix = "Th1S_WasM@De_Se2er_"
_server_comment_changed_cache = ""

# Hexray_Hooks
class Hexray_Hooks(ida_hexrays.Hexrays_Hooks):
    def cmt_changed(self, cfunc, loc, cmt):
        global _server_comment_changed_cache
        # 获取函数名
        if _general_prefix + cmt == _server_comment_changed_cache:
            _server_comment_changed_cache = ''
            return 0
        comment_ea = loc.ea
        buffer = client_edit_comment_buffer(comment_ea,cmt)
        buffer = buffer.encode()
        _server_socket.sendall(buffer)
        return 0 

# IDB hook
class IDB_Hooks(idaapi.IDB_Hooks):
    def renamed(self, ea, new_name:str, local_name, old_name):
        # print(new_name,old_name)
        if new_name.endswith(suffix) and new_name.startswith(prefix):
            return 0
        if old_name.endswith(suffix) and old_name.startswith(prefix):
            print(f"函数重命名: 0x{ea:X} -> {new_name} By server")
            return 0
        # print(f"函数重命名: 0x{ea:X} -> {new_name}")
        buffer = client_rename_func_buffer(ea,new_name)
        buffer = buffer.encode()
        _server_socket.sendall(buffer)
        return 0
    
def proto_header() -> dict:
    data = {
        "header" : "1551",
        "reversed" : base64.b64encode(b"\x00" * 4).decode("utf-8"),
        "username" : username,
        'filename' : filename,
    }
    return data

# parse buffer from server 
def parse_boardcast_buffer(buffer:bytes):
    try:
        buffer = buffer.decode()
        req = proto_to_buffer(buffer)
    except:
        return 
    if req['header'] != "1551":
        return
    clientaction = req["clientaction"]
    if clientaction == ClientAction.RENAME_FUNC.value: # parse Rename Func ACT
        ea = req['ea']
        new_name = req['new_name']
        log_success(str(ea)+" "+new_name)
        def rename_in_main_thread():
            idaapi.set_name(ea, prefix+new_name+suffix ,idaapi.SN_NOWARN)
            idaapi.set_name(ea, new_name ,idaapi.SN_NOWARN)
        idaapi.execute_sync(rename_in_main_thread, idaapi.MFF_WRITE)

    elif clientaction == ClientAction.EDIT_CMT.value:   # parse EDIT comment ACT
        comment_ea = req['comment_ea']
        cmt = req["cmt"]
        log_success(str(comment_ea)+" "+cmt)
        def edit_cmt_in_main_thread():
            global _server_comment_changed_cache
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                tl = ida_hexrays.treeloc_t()
                tl.ea = comment_ea  # 设置注释位置
                _server_comment_changed_cache = _general_prefix + cmt
                cfunc.set_user_cmt(tl, cmt)
                cfunc.save_user_cmts()  # 保存注释
            else:
                log_fail(f"Abort Comment sync in {comment_ea}")
                return 
        idaapi.execute_sync(edit_cmt_in_main_thread, idaapi.MFF_WRITE)

    else:
        log_fail("未知消息")

# client Body
def connect_server():
    global _server_socket
    _server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    _server_socket.connect((server_host,server_port))
    data = {
        "auth" : PINCODE,
        'filename' : filename,
    }
    j_data = json.dumps(data)
    _server_socket.sendall(j_data.encode())

def receive_messages():
    while not stop_flag:
        try:
            data = _server_socket.recv(1024)
            if not data:
                log_fail("与服务器的连接已断开")
                break
            # log_success(f"收到广播消息: {data}")
            parse_boardcast_buffer(data)
        except ConnectionResetError:
            log_fail("与服务器的连接被重置")
            break
        except Exception as e:
            log_fail(f"接收消息错误: {str(e)}")
            break

def run_main():
    try:
        connect_server()
    except:
        log_fail("无法连接服务器")
        exit(0)
    log_success("hook Started.")

    # 启动消息接收线程
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    idb_hook = IDB_Hooks()
    idb_hook.hook()
    hexray_hook = Hexray_Hooks()
    hexray_hook.hook()

    while not stop_flag:  # 检查终止标志
        time.sleep(5)
    log_success("hook exit.")
    idb_hook.unhook()
    hexray_hook.unhook()

thread = threading.Thread(target=run_main)
thread.start()

# 在需要终止时设置 stop_flag = True
# 例如通过另一个脚本或交互式控制