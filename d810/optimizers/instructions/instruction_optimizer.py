from __future__ import annotations
import logging
from ida_hexrays import *
from d810.optimizers.instructions.instruction_optimization_rule import InstructionOptimizationRule
from d810.format.hexrays_formatters import format_minsn_t
from d810.error.errors import D810Exception

d810_logger = logging.getLogger('D810')
optimizer_logger = logging.getLogger('D810.optimizer')

class InstructionOptimizer(object):
    RULE_CLASSES = []
    NAME = None

    def __init__(self, maturities: List[int], log_dir=None):
        self.rules = set()
        self.rules_usage_info = {}
        self.maturities = maturities
        self.log_dir = log_dir
        self.cur_maturity = MMAT_PREOPTIMIZED

    def add_rule(self, rule: InstructionOptimizationRule):
        is_valid_rule_class = False
        for rule_class in self.RULE_CLASSES:
            if isinstance(rule, rule_class):
                is_valid_rule_class = True
                break
        if not is_valid_rule_class:
            return False
        optimizer_logger.debug("Adding rule {0}".format(rule))
        if len(rule.maturities) == 0:
            rule.maturities = self.maturities
        self.rules.add(rule)
        self.rules_usage_info[rule.name] = 0
        return True

    def reset_rule_usage_statistic(self):
        self.rules_usage_info = {}
        for rule in self.rules:
            self.rules_usage_info[rule.name] = 0

    def show_rule_usage_statistic(self):
        for rule_name, rule_nb_match in self.rules_usage_info.items():
            if rule_nb_match > 0:
                d810_logger.info("Instruction Rule '{0}' has been used {1} times".format(rule_name, rule_nb_match))

    def get_optimized_instruction(self, blk: mblock_t, ins: minsn_t):
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        # if self.cur_maturity not in self.maturities:
        #     return None
        for rule in self.rules:
            if self.cur_maturity not in rule.maturities:
                continue
            try:
                new_ins = rule.check_and_replace(blk, ins)
                if new_ins is not None:
                    self.rules_usage_info[rule.name] += 1
                    optimizer_logger.info("Rule {0} matched:".format(rule.name))
                    optimizer_logger.info("  orig: {0}".format(format_minsn_t(ins)))
                    optimizer_logger.info("  new : {0}".format(format_minsn_t(new_ins)))
                    return new_ins
            except RuntimeError as e:
                optimizer_logger.error("Runtime error during rule {0} for instruction {1}: {2}".format(rule, format_minsn_t(ins), e))
            except D810Exception as e:
                optimizer_logger.error("D810Exception during rule {0} for instruction {1}: {2}".format(rule, format_minsn_t(ins), e))
        return None

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__
