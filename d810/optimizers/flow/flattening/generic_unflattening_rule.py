from d810.optimizers.flow.flow_optimization_rule import FlowOptimizationRule
from ida_hexrays import *


class GenericUnflatteningRule(FlowOptimizationRule):
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2]

    def __init__(self):
        super().__init__()
        self.mba = None
        self.cur_maturity = MMAT_ZERO
        self.cur_maturity_pass = 0
        self.last_pass_nb_patch_done = 0
        self.maturities = self.DEFAULT_UNFLATTENING_MATURITIES

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if self.cur_maturity == self.mba.maturity:
            self.cur_maturity_pass += 1
        else:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            return False
        return True