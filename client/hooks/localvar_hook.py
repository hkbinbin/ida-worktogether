import ida_hexrays
import idaapi
import json
import socket
from dataclasses import dataclass
from proto_ import proto_header
from config_ import ClientAction
import config_
import general_func
@dataclass
class VarInfo:
    # var type
    typeinfo: str
    lvarname: str
    # var location
    arg_location: str
    arg_idx: int
    # comment
    comment: str

def local_var_renamed_buffer(varinfo: VarInfo, func_ea) -> str:
    proto_buffer = proto_header()
    proto_buffer["clientaction"] = ClientAction.RENAME_LVAR.value
    proto_buffer["index_ea"] = func_ea
    proto_buffer["func_ea"] = func_ea
    proto_buffer["param_index"] = varinfo.arg_idx
    proto_buffer["new_name"] = varinfo.lvarname
    proto_buffer["typeinfo"] = varinfo.typeinfo
    proto_buffer["comment"] = varinfo.comment
    json_buffer = json.dumps(proto_buffer)
    return json_buffer

def request_lvar_infomation(index_ea) -> str:
    proto_buffer = proto_header()
    proto_buffer["clientaction"] = ClientAction.REQUEST_LVAR.value
    proto_buffer["index_ea"] = index_ea
    json_buffer = json.dumps(proto_buffer)
    return json_buffer

_localvar_general_prefix = "Th1S_WasM@De_Se2er_"
_server_raname_localvar_cache = ""
class LocalvarHexrayHooks(ida_hexrays.Hexrays_Hooks):
    # funcs_table(hash table) to check if var types has already loaded in old_var_types
    funcs_table = set()
    old_var_types = {}
    mutex_func_printed: bool = False

    def cache_func_vars(self, cfunc):
        ea = cfunc.entry_ea
        if ea not in self.funcs_table:
            self.funcs_table.add(ea) # add address
            lvars = cfunc.get_lvars()
            value = []
            for idx, lv in enumerate(lvars):
                lv_node = VarInfo(typeinfo=lv.tif.dstr(),
                        lvarname=lv.name,
                        arg_location="arg" if lv.is_arg_var else "stk" if lv.is_stk_var() else "reg",
                        arg_idx=idx,
                        comment=lv.cmt)
                value.append(lv_node) #store (name, type, location)
            self.old_var_types[ea] = value
            print(f"[Hook] cache: {self.old_var_types}") # all hook
        return 0
    
    # store var old type
    # func_printed() => cache_func_vars
    # work when F5
    def func_printed(self, cfunc):
        self.cache_func_vars(cfunc)
        if self.mutex_func_printed == False:
            # request edit with server 
            buffer = request_lvar_infomation(cfunc.entry_ea)
            buffer = buffer.encode()
            # config_._server_socket.sendall(buffer)
            # config_._server_socket.settimeout(0.2)
            sub_socket = general_func.sub_connect_server()
            sub_socket.sendall(buffer)
            sub_socket.settimeout(2)
            try:
                while True: # cycle for json_list
                    json_data = b''
                    end: bool = False
                    while True: # cycle for full json data
                        data = sub_socket.recv(1024)
                        print(data)
                        if data.endswith(b"E0@F"):
                            data = data[:-4]
                            # recv once json done
                            raw_json = json.loads(json_data.decode())
                            index = raw_json["param_index"]
                            new_name = raw_json["new_name"]
                            new_type_str = raw_json["typeinfo"]
                            lvars = cfunc.get_lvars()
                            lvar = lvars[index]
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
                            
                            config_._server_socket.sendall("ACK".encode()) # send ACK
                            break
                        if data.startswith(b"END"):
                            end = True
                            break
                        else:
                            json_data += data
                    if end:
                        # refresh view
                        break
                        

            except socket.timeout:
                print(f"Timeout")
                return -1
            except Exception as e:
                print(f"Error: {e}")
                return -1

            # refresh code force
            sub_socket.close()
            config_._server_socket.settimeout(2)
            self.mutex_func_printed = True
            cfunc.refresh_func_ctext()
            return 1
        else:
            self.mutex_func_printed = False
        return 0
    # func var type change hook
    def lvar_type_changed(self, vu, v, tinfo):
        ea = vu.cfunc.entry_ea
        # print(f"[Hook] v: {v.tif}")
        cached = self.old_var_types.get(ea, None)
        if not cached:
            # case change from server (cache mismatch)
            # add cache first
            cfunc = vu.cfunc
            self.cache_func_vars(cfunc)
            cached = self.old_var_types.get(ea, None)

        if not cached:
            return -1 # error
        
        # find type from set
        old_type = None
        for i, lvnode in enumerate(cached):
            if lvnode.lvarname == v.name:
                old_type = lvnode.typeinfo
                print(f"[Hook] In function addr: {vu.cfunc.entry_ea}")
                # print(f"[Hook] Var name: {v.name}")
                # print(f"[Hook] Changed var width: {v.width}")
                print(f"[Hook] Var Old type: {old_type}")
                print(f"[Hook] Var New type: {tinfo.dstr()}")
                cached[i].typeinfo = tinfo.dstr() # update
                return 0
            
        return -1 # error

    # func var name change hook
    def lvar_name_changed(self, vu, v, name, is_user_name):
        if _localvar_general_prefix + name == _server_raname_localvar_cache:
            return 0
        ea = vu.cfunc.entry_ea
        cached = self.old_var_types.get(ea, None)
        if not cached:
            # case change from server (cache mismatch)
            # add cache first
            cfunc = vu.cfunc
            self.cache_func_vars(cfunc)
            cached = self.old_var_types.get(ea, None)
        
        if not cached:
            return -1 # error

        cfunc = vu.cfunc
        lvars = cfunc.get_lvars()
        for i, lv in enumerate(lvars):
            # check arg var
            if lv.is_arg_var:
                # check mismatch in cache
                if(lv.name != cached[i].lvarname):
                    # print(f"[Hook] In function addr: {ea}")
                    # print(f"[Hook] Old Var name: {cached[i].lvarname}")
                    # print(f"[Hook] New Var name: {name}")
                    cached[i].lvarname = name # update
                    buffer = local_var_renamed_buffer(cached[i],ea)
                    buffer = buffer.encode()
                    config_._server_socket.sendall(buffer)
                    return 0
            else:
                # del with normal vars
                if(lv.name != cached[i].lvarname):
                    cached[i].lvarname = name
                    buffer = local_var_renamed_buffer(cached[i],ea)
                    buffer = buffer.encode()
                    config_._server_socket.sendall(buffer)
                    return 0

        return -1 # error
