import idaapi
import ida_hexrays
import ida_kernwin


from d810.state_manager import StateManager
D810_VERSION = "0.1"

class D810Plugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "D-810"
    wanted_hotkey = "Ctrl-Shift-Alt-Z"
    comment = "Interface to the D-810 plugin"
    help = ""
    initialized = False

    def __init__(self):
        super(D810Plugin, self).__init__()
        self.state_manager = None
        self.gui = None
        self.initialized = False

    def start_plugin(self):
        from d810.ui.ida_ui import D810GUI
        self.state_manager.start()
        self.gui = D810GUI()
        self.gui.show_windows()

    def stop_plugin(self):
        self.state_manager.stop()
        if self.gui:
            self.gui.term()
            self.gui = None

    # IDA API methods: init, run, term
    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("D-810 need Hex-Rays decompiler. Skipping")
            return idaapi.PLUGIN_SKIP
        if not ida_kernwin.is_idaq():
            print("D-810 need IDA UI. Skipping")
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print("D-810 need IDA version >= 7.5. Skipping")
            return idaapi.PLUGIN_SKIP

        self.state_manager = StateManager()
        print("D-810 initialized (version {0})".format(D810_VERSION))
        return idaapi.PLUGIN_OK


    def run(self, args):
        self.start_plugin()


    def term(self):
        print("Terminating D-810...")
        if self.state_manager is not None:
            self.state_manager.stop()

        self.initialized = False


def PLUGIN_ENTRY():
    return D810Plugin()
