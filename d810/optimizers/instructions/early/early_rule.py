from d810.optimizers.instructions.generic_pattern_rule import GenericPatternRule
from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizer


class EarlyRule(GenericPatternRule):
    pass


class EarlyOptimizer(InstructionOptimizer):
    RULE_CLASSES = [EarlyRule]
