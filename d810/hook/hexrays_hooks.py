from __future__ import annotations
from d810.log.log import main_logger
from ida_gdl import qflow_chart_t
from ida_hexrays import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.optimizer_manager import OptimizerManager
    from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizer, InstructionOptimizationRule
    from d810.optimizers.flow.flow_optimization_rule import FlowOptimizationRule

class HexraysDecompilationHook(Hexrays_Hooks):
    def __init__(self, manager: OptimizerManager):
        super().__init__()
        self.manager = manager

    def prolog(self, mba: mbl_array_t, fc: qflow_chart_t, reachable_blocks, decomp_flags) -> "int":
        main_logger.info("Starting decompilation of function at 0x{0:x}".format(mba.entry_ea))
        self.manager.instruction_optimizer.reset_rule_usage_statistic()
        self.manager.block_optimizer.reset_rule_usage_statistic()
        return 0

    def glbopt(self, mba: mbl_array_t) -> "int":
        main_logger.info("glbopt finished for function at 0x{0:x}".format(mba.entry_ea))
        self.manager.instruction_optimizer.show_rule_usage_statistic()
        self.manager.block_optimizer.show_rule_usage_statistic()
        return 0
