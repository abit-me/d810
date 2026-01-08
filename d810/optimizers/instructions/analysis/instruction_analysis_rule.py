from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizationRule


class InstructionAnalysisRule(InstructionOptimizationRule):
    def analyze_instruction(self, blk, ins):
        raise NotImplementedError