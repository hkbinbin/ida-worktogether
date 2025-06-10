import ida_hexrays
import idaapi

# funcs_table(hash table) to check if var types has already loaded in old_var_types
funcs_table = set()
old_var_types = {}

class FunctionHexrayHooks(ida_hexrays.Hexrays_Hooks):
    # store var old type
    def func_printed(self, vu):
        ea = vu.entry_ea
        if ea not in funcs_table:
            funcs_table.add(ea) # add address
            lvars = vu.get_lvars()
            value = set()
            for lv in lvars:
                value.add((lv.name, lv.tif.copy().dstr())) # store (name, type)
            old_var_types[ea] = value
            print(f"[Hook] cache: {old_var_types}")
        return 0

    # func var type change hook
    def lvar_type_changed(self, vu, v, tinfo):
        key = vu.cfunc.entry_ea
        # print(f"[Hook] v: {v.tif}")
        cached = old_var_types.get(key, None)
        if cached:
            # find type from set
            old_type = None
            for var_name, var_tinfo in cached:
                if var_name == v.name:
                    old_type = var_tinfo
                    break
            if old_type == None:
                # case change from server
                return
            print(f"[Hook] In function addr: {vu.cfunc.entry_ea}")
            print(f"[Hook] Var name: {v.name}")
            print(f"[Hook] Changed var width: {v.width}")
            print(f"[Hook] Var Old type: {old_type}")
            print(f"[Hook] Var New type: {tinfo.dstr()}")
            old_var_types[key] = (v.name, tinfo.dstr())
        else:
            # case change from server
            print(f"[Hook] Var name: {v.name} - no old type cached")

    # func var name change hook
    def lvar_name_changed(self, vu, v, name, is_user_name):
        key = vu.cfunc.entry_ea
        cached = old_var_types.get(key, None)
        if cached:
            old_name = None
            for var_name, var_tinfo in cached:
                if var_tinfo == v.tif.dstr():
                    old_name = var_name
                    break
            if old_name == None:
                # case change from server
                return
            old_var_types[key] = (name, v.tif.dstr())
            print(f"[Hook] In function addr: {vu.cfunc.entry_ea}")
            print(f"[Hook] Old Var name: {old_name}")
            print(f"[Hook] New Var name: {name}")
        else:
            # case change from server
            print(f"[Hook] no old name cached")


function_hook = FunctionHexrayHooks()
function_hook.hook()