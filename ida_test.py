import idaapi

class MyIDBHook(idaapi.IDB_Hooks):
    def func_deleted(self, pfn):
        print(f"[Hook] Function updated: {pfn}")
        return 0  # 返回 0 以允许该操作
    def segm_added(self, s):
        print(f"[Hook] Segm added: {s}")
        return 0  # 返回 0 以允许该操作
    def lt_udm_changed(self,udtname,udm_tid,udmold,udmnew ):
        print(f"[Hook] udtname:{udtname}, udm_tid:{udm_tid}, udmold:{udmold.type}, udmnew:{udmnew.type}" )
        return 0

    def local_types_changed(self, ltc, ordinal, name):
        print(f"[Hook] ltc: {ltc}, ordinal: {ordinal}, name: {name}")
        return 0

# 实例化并注册 hook
my_hook = MyIDBHook()
my_hook.hook()

print("[*] Function update hook installed.")


import ida_hexrays

class MyHexraysHooks(ida_hexrays.Hexrays_Hooks):
    def lvar_type_changed(self, vu, v, tinfo):
        print(f"[+] 变量修改事件：函数")
        return 0

# 创建并激活 hook
hx_hooks = MyHexraysHooks()
hx_hooks.hook()

print("[*] 正在监听局部变量类型修改 (Shift+Y)...")
