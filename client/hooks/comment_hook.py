import idaapi
import json
import ida_hexrays
from proto_ import proto_header
from config_ import *
import config_
# Comment hook

# global var used in hooks -> ignore it
_comment_general_prefix = "Th1S_WasM@De_Se2er_"
_server_comment_changed_cache = ""


def client_edit_comment_buffer(comment_ea:int, cmt:str) -> str:
    proto_buffer = proto_header()
    proto_buffer["index_ea"] = comment_ea
    proto_buffer["clientaction"] = ClientAction.EDIT_CMT.value
    proto_buffer["comment_ea"] = comment_ea
    proto_buffer["cmt"] = cmt
    json_buffer = json.dumps(proto_buffer)
    return json_buffer


# Hexray_Hooks
class CommentHexrayHooks(ida_hexrays.Hexrays_Hooks):
    def cmt_changed(self, cfunc, loc, cmt):
        global _server_comment_changed_cache
        # 获取函数名
        if _comment_general_prefix + cmt == _server_comment_changed_cache:
            _server_comment_changed_cache = ''
            return 0
        comment_ea = loc.ea
        buffer = client_edit_comment_buffer(comment_ea,cmt)
        buffer = buffer.encode()
        buffer += b'\r\n'
        config_._server_socket.sendall(buffer)
        return 0 