import idc
import idaapi

def rename_function_param(func_ea, param_index, new_name):
    tinfo = idaapi.tinfo_t()
    if not idaapi.get_tinfo(tinfo, func_ea):
        return False

    func_type_data = idaapi.func_type_data_t()
    if not tinfo.get_func_details(func_type_data):
        return False

    if param_index >= len(func_type_data):
        print("Index out of range")
        return False

    func_type_data[param_index].name = new_name
    tinfo.create_func(func_type_data)

    success = idaapi.apply_tinfo(func_ea, tinfo, idaapi.TINFO_DEFINITE)
    if success:
        print(f"1 {hex(func_ea)} 2 {param_index} 3 {new_name}")
    else:
        print("apply_tinfo failed")
    return success


rename_function_param(0x0014002A5DC, 3, "sbhkbin")  # rdx 是参数 1
