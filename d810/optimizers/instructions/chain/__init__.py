from d810.expr.utils import get_all_subclasses
from d810.optimizers.instructions.chain.chain_optimizer import ChainSimplificationRule, ChainOptimizer
from d810.optimizers.instructions.chain.chain_rules import *

CHAIN_RULES = [x() for x in get_all_subclasses(ChainSimplificationRule)]
