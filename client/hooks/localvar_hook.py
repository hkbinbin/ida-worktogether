import ida_hexrays
import idaapi
import json
from dataclasses import dataclass
from proto_ import proto_header
from config_ import ClientAction
import config_

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

def local_var_renamed_buffer(func_ea, param_index, new_name) -> str:
    proto_buffer = proto_header()
    proto_buffer["clientaction"] = ClientAction.RENAME_LVAR.value
    proto_buffer["func_ea"] = func_ea
    proto_buffer["param_index"] = param_index
    proto_buffer["new_name"] = new_name
    json_buffer = json.dumps(proto_buffer)
    return json_buffer

_localvar_general_prefix = "Th1S_WasM@De_Se2er_"
_server_raname_localvar_cache = ""
class LocalvarHexrayHooks(ida_hexrays.Hexrays_Hooks):
    # funcs_table(hash table) to check if var types has already loaded in old_var_types
    funcs_table = set()
    old_var_types = {}

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
        return self.cache_func_vars(cfunc)

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
                    buffer = local_var_renamed_buffer(ea,i,name)
                    buffer = buffer.encode()
                    config_._server_socket.sendall(buffer)
                    cached[i].lvarname = name # update
                    return 0

        return -1 # error
