from d810.format.hexrays_formatters import maturity_to_string
from d810.log.log import optimizer_logger, main_logger
from d810.optimizers.flow.flow_optimization_rule import FlowOptimizationRule
from ida_hexrays import *


class BlockOptimizerManager(optblock_t):
    def __init__(self):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.cfg_rules = set()

        self.current_maturity = None
        self.cfg_rules_usage_info = {}

    def func(self, blk: mblock_t):
        self.log_info_on_input(blk)
        nb_patch = self.optimize(blk)
        return nb_patch

    def reset_rule_usage_statistic(self):
        self.cfg_rules_usage_info = {}
        for rule in self.cfg_rules:
            self.cfg_rules_usage_info[rule.name] = []

    def show_rule_usage_statistic(self):
        for rule_name, rule_nb_patch_list in self.cfg_rules_usage_info.items():
            nb_use = len(rule_nb_patch_list)
            if nb_use > 0:
                main_logger.info("BlkRule '{0}' has been used {1} times for a total of {2} patches".format(rule_name, nb_use, sum(rule_nb_patch_list)))

    def log_info_on_input(self, blk: mblock_t):
        if blk is None:
            return
        mba: mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            main_logger.debug("BlockOptimizer called at maturity: {0}".format(maturity_to_string(mba.maturity)))
            self.current_maturity = mba.maturity

    def optimize(self, blk: mblock_t) -> int:
        for cfg_rule in self.cfg_rules:
            if self.check_if_rule_is_activated_for_address(cfg_rule, blk.mba.entry_ea):
                nb_patch = cfg_rule.optimize(blk)
                if nb_patch > 0:
                    optimizer_logger.info("Rule {0} matched: {1} patches".format(cfg_rule.name, nb_patch))
                    self.cfg_rules_usage_info[cfg_rule.name].append(nb_patch)
                    return nb_patch
        return 0

    def add_rule(self, cfg_rule: FlowOptimizationRule):
        optimizer_logger.info("Adding cfg rule {0}".format(cfg_rule))
        self.cfg_rules.add(cfg_rule)
        self.cfg_rules_usage_info[cfg_rule.name] = []

    def configure(self, **kwargs):
        pass

    def check_if_rule_is_activated_for_address(self, cfg_rule: FlowOptimizationRule, func_entry_ea: int):
        if cfg_rule.use_whitelist and (func_entry_ea not in cfg_rule.whitelisted_function_ea_list):
            return False
        if cfg_rule.use_blacklist and (func_entry_ea in cfg_rule.blacklisted_function_ea_list):
            return False
        return True