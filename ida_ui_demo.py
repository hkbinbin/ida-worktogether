# myplugin.py

import idaapi
import ida_kernwin

PLUGIN_NAME = "IDA-WorkTogether"
PLUGIN_HOTKEY = "Ctrl+Alt+U"

class IDAWorkTogether(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDA Realtime Sync"
    help = "UI control panel"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print("[*] IDA-WorkTogether initialized")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # ida_kernwin.info("Plugin UI Triggered!")
        self.show_ui()

    def term(self):
        print("[*] IDA-WorkTogether terminated")

    def show_ui(self):
        form_code = r"""
            IDA-WorkTogether
    
            <~Connect / Disconnect~:{btn1}>
            
        """

        class MyForm(ida_kernwin.Form):
            def __init__(self):
                super(MyForm, self).__init__(form_code, {
                    'btn1': ida_kernwin.Form.ButtonInput(self.OnButton),
                })

            def on_button(self, code=0):
                pass

            def OnButton(self, fid):
                print("trigger")
                return 1

        f = MyForm()
        f.Compile()
        f.Execute()
        f.Free()

def PLUGIN_ENTRY():
    return IDAWorkTogether()
