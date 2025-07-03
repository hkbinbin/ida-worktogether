import threading
import time
import socket
import idaapi
import json
import ida_hexrays
import sys
import os

# custom code 
from proto_ import *
import config_

script_dir = os.path.dirname(os.path.abspath(__file__))
# add search path
if script_dir not in sys.path:
    sys.path.append(script_dir)

import hooks.comment_hook
import hooks.function_hook
import hooks.localvar_hook

hooks_table = [hooks.comment_hook.CommentHexrayHooks(),hooks.function_hook.FunctionIDBHook(),hooks.localvar_hook.LocalvarHexrayHooks()]

# log_func 
def log_fail(msg):
    print("[-] Fail:",end='')
    print(msg)
def log_success(msg):
    print("[+] success:",end='')
    print(msg)

# proto parse Func
def proto_to_buffer(json_str:str) -> dict:
    json_obj = json.loads(json_str)
    return json_obj

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
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                tl = ida_hexrays.treeloc_t()
                tl.ea = comment_ea  # set cmt location
                hooks.comment_hook._server_comment_changed_cache = hooks.comment_hook._comment_general_prefix + cmt
                cfunc.set_user_cmt(tl, cmt)
                cfunc.save_user_cmts()  # keep cmt
            else:
                log_fail(f"Abort Comment sync in {comment_ea}")
                return 
        idaapi.execute_sync(edit_cmt_in_main_thread, idaapi.MFF_WRITE)

    elif clientaction == ClientAction.RENAME_LVAR.value:
        func_ea = req["func_ea"] 
        param_index = req["param_index"]
        new_name = req["new_name"]
        new_type_str = req["typeinfo"]
        log_success(f"{func_ea} {param_index} {new_name}")
        def rename_localvar_in_main_thread():
            cfunc = ida_hexrays.decompile(ea)
            lvars = cfunc.get_lvars()
            lvar = lvars[param_index]
            lvar.name = new_name
            new_tinfo = idaapi.tinfo_t()
            til = idaapi.cvar.idati
            decl = f"{new_type_str} {new_name};"
            if not idaapi.parse_decl(new_tinfo, til, decl, idaapi.PT_SIL):
                print(f"parsing var type fail: {decl}")
                return -1
            if not lvar.set_lvar_type(new_tinfo):
                print("set var type fail")
                return -1
            uservec = ida_hexrays.lvar_uservec_t()
            for v in lvars:
                uservec.keep_info(v)
            func_ea = cfunc.entry_ea
            ida_hexrays.save_user_lvar_settings(func_ea, uservec)
        hooks.localvar_hook._server_raname_localvar_cache = hooks.localvar_hook._localvar_general_prefix + new_name
        idaapi.execute_sync(rename_localvar_in_main_thread, idaapi.MFF_WRITE)

    else:
        log_fail("unknown message")

# client Body
def connect_server():
    config_._server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    config_._server_socket.connect((server_host,server_port))
    data = {
        "auth" : PINCODE,
        'filename' : filename,
        'sub' : 0,
    }
    j_data = json.dumps(data)
    config_._server_socket.sendall(j_data.encode())
    data = config_._server_socket.recv(24)
    if data.startswith(b"ACKed"):
        return
    else:
        raise("Error")

def process_messages():
    while True:
        if config_.msg_int_flag == False:
            time.sleep(0.5)
        else:
            print("get one")
            data = config_.msg_queue.get()
            parse_boardcast_buffer(data)

def receive_messages():
    while not stop_flag:
        try:
            data = config_._server_socket.recv(1024)
            if not data:
                log_fail("disconnect with server")
                break
            # log_success(f": {data}")
            print("put one")
            config_.msg_queue.put(data)
        except ConnectionResetError:
            log_fail("connection reset")
            break
        except Exception as e:
            log_fail(f"recv msg error: {str(e)}")
            break

def start_hook():
    for hook in hooks_table:
        hook.hook()

def destory_hook():
    for hook in hooks_table:
        hook.unhook()

def run_main():
    try:
        connect_server()
    except:
        log_fail("Cound not connect to server")
        exit(0)
    log_success("hook Started.")
    start_hook()
    # start msg recv thread
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()
    process_thread = threading.Thread(target=process_messages, daemon=True)
    process_thread.start()

    while not stop_flag:  # check stop flag
        time.sleep(5)
    destory_hook()
    log_success("hook exit.")
    

thread = threading.Thread(target=run_main)
thread.start()

# stop_flag = True