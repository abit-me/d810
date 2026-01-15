from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # 仅在类型检查时导入，运行时不执行
    from d810.optimizers.instruction_optimizer_manager import InstructionOptimizerManager


from d810.log.log import optimizer_logger
from ida_hexrays import *

class InstructionVisitorManager(minsn_visitor_t):
    def __init__(self, optimizer: InstructionOptimizerManager):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.instruction_optimizer = optimizer

    def visit_minsn(self) -> bool:
        return self.instruction_optimizer.optimize(self.blk, self.curins)
