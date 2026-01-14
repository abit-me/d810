from ida_hexrays import vd_printer_t


class block_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.block_ins = []

    def get_block_mc(self):
        return "\n".join(self.block_ins)

    def _print(self, indent, line):
        self.block_ins.append("".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line]))
        return 1