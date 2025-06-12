import ida_hexrays
import idaapi
from dataclasses import dataclass

@dataclass
class VarInfo:
    # var type
    typeinfo: str
    typename: str
    # var location
    arg_location: str
    arg_idx: int
    # comment
    comment: str

# funcs_table(hash table) to check if var types has already loaded in old_var_types
funcs_table = set()
old_var_types = {}

class FunctionHexrayHooks(ida_hexrays.Hexrays_Hooks):
    def cache_func_vars(self, cfunc):
        ea = cfunc.entry_ea
        if ea not in funcs_table:
            funcs_table.add(ea) # add address
            lvars = cfunc.get_lvars()
            value = []
            for idx, lv in enumerate(lvars):
                lv_node = VarInfo(typeinfo=lv.tif.dstr(),
                        typename=lv.name,
                        arg_location="arg" if lv.is_arg_var else "stk" if lv.is_stk_var() else "reg",
                        arg_idx=idx,
                        comment=lv.cmt)
                value.append(lv_node) #store (name, type, location)
            old_var_types[ea] = value
            print(f"[Hook] cache: {old_var_types}")
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
        cached = old_var_types.get(ea, None)
        if not cached:
            # case change from server (cache mismatch)
            # add cache first
            cfunc = vu.cfunc
            self.cache_func_vars(cfunc)
            cached = old_var_types.get(ea, None)

        if not cached:
            return -1 # error
        
        # find type from set
        old_type = None
        for i, lvnode in enumerate(cached):
            if lvnode.typename == v.name:
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
        ea = vu.cfunc.entry_ea
        cached = old_var_types.get(ea, None)
        if not cached:
            # case change from server (cache mismatch)
            # add cache first
            cfunc = vu.cfunc
            self.cache_func_vars(cfunc)
            cached = old_var_types.get(ea, None)
        
        if not cached:
            return -1 # error

        cfunc = vu.cfunc
        lvars = cfunc.get_lvars()
        for i, lv in enumerate(lvars):
            # check arg var
            if lv.is_arg_var:
                # check mismatch in cache
                if(lv.name != cached[i].typename):
                    print(f"[Hook] In function addr: {ea}")
                    print(f"[Hook] Old Var name: {cached[i].typename}")
                    print(f"[Hook] New Var name: {name}")
                    cached[i].typename = name # update
                    return 0

        return -1 # error


# function_hook = FunctionHexrayHooks()
# function_hook.hook()