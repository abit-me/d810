from d810.optimizers.optimization_rule import OptimizationRule
from ida_hexrays import *

class InstructionOptimizationRule(OptimizationRule):
    def __init__(self):
        super().__init__()
        self.maturities = []

    def check_and_replace(self, blk: mblock_t, ins: minsn_t):
        return None