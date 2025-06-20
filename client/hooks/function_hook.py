import idaapi
import json

from proto_ import proto_header
from config_ import ClientAction,suffix,prefix
import config_
# Comment hook

def client_rename_func_buffer(ea, new_name) -> str:
    proto_buffer = proto_header()
    proto_buffer["index_ea"] = ea
    proto_buffer["clientaction"] = ClientAction.RENAME_FUNC.value
    proto_buffer["ea"] = ea
    proto_buffer["new_name"] = new_name
    json_buffer = json.dumps(proto_buffer)
    return json_buffer

class FunctionIDBHook(idaapi.IDB_Hooks):
    def renamed(self, ea, new_name:str, local_name, old_name):
        # print(new_name,old_name)
        if new_name.endswith(suffix) and new_name.startswith(prefix):
            return 0
        if old_name.endswith(suffix) and old_name.startswith(prefix):
            print(f"function rename: 0x{ea:X} -> {new_name} By server")
            return 0
        buffer = client_rename_func_buffer(ea,new_name)
        buffer = buffer.encode()
        config_._server_socket.sendall(buffer)
        return 0
    