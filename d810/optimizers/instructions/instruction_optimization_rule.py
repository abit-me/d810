from d810.optimizers.optimization_rule import OptimizationRule


class InstructionOptimizationRule(OptimizationRule):
    def __init__(self):
        super().__init__()
        self.maturities = []

    def check_and_replace(self, blk, ins):
        return None