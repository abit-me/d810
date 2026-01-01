import ida_hexrays

class TestHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        self.triggered = False

    # def prolog(self, mba: 'mba_t', fc: 'qflow_chart_t', reachable_blocks: 'bitset_t', decomp_flags: int) -> int:
    def prolog(self, mba: ida_hexrays.mbl_array_t, fc, reachable_blocks, decomp_flags) -> "int":
        print("[TEST] prolog hook triggered!")
        self.triggered = True
        return 0

test_hook = TestHook()