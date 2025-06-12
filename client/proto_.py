from config_ import *
import base64
def proto_header() -> dict:
    data = {
        "header" : "1551",
        "reversed" : base64.b64encode(b"\x00" * 4).decode("utf-8"),
        "username" : username,
        'filename' : filename,
    }
    return data