from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizationRule, InstructionOptimizer


class ChainSimplificationRule(InstructionOptimizationRule):
    pass


class ChainOptimizer(InstructionOptimizer):
    RULE_CLASSES = [ChainSimplificationRule]
