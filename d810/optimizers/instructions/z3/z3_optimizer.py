from d810.optimizers.instructions.generic_pattern_rule import GenericPatternRule
from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizer


class Z3Rule(GenericPatternRule):
    pass


class Z3Optimizer(InstructionOptimizer):
    RULE_CLASSES = [Z3Rule]
