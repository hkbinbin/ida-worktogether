import ida_hexrays
import idaapi

# funcs_table(hash table) to check if var types has already loaded in old_var_types
funcs_table = set()
old_var_types = {}

class FunctionHexrayHooks(ida_hexrays.Hexrays_Hooks):
    # store var old type
    # func_printed() => cfunc->get_lvars()
    def func_printed(self, cfunc):
        ea = cfunc.entry_ea
        if ea not in funcs_table:
            funcs_table.add(ea) # add address
            lvars = cfunc.get_lvars()
            value = []
            for lv in lvars:
                value.append((lv.name, lv.tif.copy().dstr())) #store (name, type, location)
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
            for i, (var_name, var_tinfo) in enumerate(cached):
                if var_name == v.name:
                    old_type = var_tinfo
                    print(f"[Hook] In function addr: {vu.cfunc.entry_ea}")
                    print(f"[Hook] Var name: {v.name}")
                    print(f"[Hook] Changed var width: {v.width}")
                    print(f"[Hook] Var Old type: {old_type}")
                    print(f"[Hook] Var New type: {tinfo.dstr()}")
                    cached[i] = (v.name, tinfo.dstr()) # update
                    break
        # case change from server
        print(f"[Hook] Var name: {v.name} - no old type cached")

    # func var name change hook
    def lvar_name_changed(self, vu, v, name, is_user_name):
        key = vu.cfunc.entry_ea
        cached = old_var_types.get(key, None)
        if cached:
            cfunc = vu.cfunc
            lvars = cfunc.get_lvars()
            new_value = []
            for lv in lvars:
                value.append((lv.name, lv.tif.copy().dstr())) #store (name, type, location)
            old_name = None
            for i, (var_name, var_tinfo) in enumerate(cached):
                
                # if (v.location.compare(var_location)): #TODO store (name, type, location) need better method to distinguish variables
                #     old_name = var_name
                #     cached[i] = (name, v.tif.dstr(), v)
                #     print(f"[Hook] In function addr: {key}")
                #     print(f"[Hook] Old Var name: {old_name}")
                #     print(f"[Hook] New Var name: {name}")
                #     return
        # case change from server
        print(f"[Hook] no old name cached")


function_hook = FunctionHexrayHooks()
function_hook.hook()