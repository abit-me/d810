import logging
from d810.optimizers.flow.jumps.jump_optimization_rule import JumpOptimizationRule
from ida_hexrays import *
from d810.expr.ast import mop_to_ast
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.optimizers.flow.flow_optimization_rule import FlowOptimizationRule
from d810.hexrays.cfg_util import make_2way_block_goto, is_conditional_jump, change_2way_block_conditional_successor


logger = logging.getLogger("D810.branch_fixer")
optimizer_logger = logging.getLogger('D810.optimizer')


class JumpFixer(FlowOptimizationRule):
    def __init__(self):
        super().__init__()
        self.known_rules = []
        self.rules = []

    def register_rule(self, rule: JumpOptimizationRule):
        self.known_rules.append(rule)

    def configure(self, kwargs):
        super().configure(kwargs)

        self.rules.clear()
        if "enabled_rules" in self.config.keys():
            for rule in self.known_rules:
                if rule.name in self.config["enabled_rules"]:
                    rule.configure()
                    self.rules.append(rule)
                    optimizer_logger.debug("JumpFixer enables rule {0}".format(rule.name))
                else:
                    optimizer_logger.debug("JumpFixer disables rule {0}".format(rule.name))

    def optimize(self, blk: mblock_t) -> bool:
        if not is_conditional_jump(blk):
            return False
        left_ast = mop_to_ast(blk.tail.l)
        right_ast = mop_to_ast(blk.tail.r)
        for rule in self.rules:
            try:
                new_ins = rule.check_pattern_and_replace(blk, blk.tail, left_ast, right_ast)
                if new_ins:
                    optimizer_logger.info("Rule {0} matched:".format(rule.name))
                    optimizer_logger.info("  orig: {0}".format(format_minsn_t(blk.tail)))
                    optimizer_logger.info("  new : {0}".format(format_minsn_t(new_ins)))
                    if new_ins.opcode == m_goto:
                        make_2way_block_goto(blk, new_ins.d.b)
                    else:
                        change_2way_block_conditional_successor(blk, new_ins.d.b)
                        blk.make_nop(blk.tail)
                        blk.insert_into_block(new_ins, blk.tail)
                        return True
            except RuntimeError as e:
                optimizer_logger.error("Error during rule {0} for instruction {1}: {2}"
                                       .format(rule, format_minsn_t(blk.tail), e))
        return False
