from ida_hexrays import vd_printer_t


class mba_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append("".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line])+"\n")
        return 1
