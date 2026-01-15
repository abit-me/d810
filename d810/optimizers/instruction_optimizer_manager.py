from __future__ import annotations
from d810.error.errors import D810Exception
from d810.format.hexrays_formatters import format_minsn_t, dump_microcode_for_debug, maturity_to_string
from d810.helper.hexrays_helpers import check_ins_mop_size_are_ok
from d810.helper.z3_util import log_z3_instructions
from d810.log.log import optimizer_logger, main_logger
from d810.optimizers.instruction_visitor_manager import InstructionVisitorManager
from d810.optimizers.instructions import PatternOptimizer, ChainOptimizer, Z3Optimizer, EarlyOptimizer, InstructionAnalyzer
from d810.optimizers.instructions.instruction_optimization_rule import InstructionOptimizationRule
from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizer
from ida_hexrays import *

DEFAULT_OPTIMIZATION_PATTERN_MATURITIES = [MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1]
DEFAULT_OPTIMIZATION_CHAIN_MATURITIES = [MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1]
DEFAULT_OPTIMIZATION_Z3_MATURITIES = [MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1]
DEFAULT_OPTIMIZATION_EARLY_MATURITIES = [MMAT_GENERATED, MMAT_PREOPTIMIZED]
DEFAULT_ANALYZER_MATURITIES = [MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1]


class InstructionOptimizerManager(optinsn_t):
    def __init__(self, log_dir: str):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.log_dir = log_dir
        self.instruction_visitor = InstructionVisitorManager(self)
        self._last_optimizer_tried = None
        self.current_maturity = None
        self.current_blk_serial = None
        self.generate_z3_code = False
        self.dump_intermediate_microcode = False

        self.instruction_optimizers = []
        self.optimizer_usage_info = {}
        self.add_optimizer(PatternOptimizer(DEFAULT_OPTIMIZATION_PATTERN_MATURITIES, log_dir=self.log_dir))
        self.add_optimizer(ChainOptimizer(DEFAULT_OPTIMIZATION_CHAIN_MATURITIES, log_dir=self.log_dir))
        self.add_optimizer(Z3Optimizer(DEFAULT_OPTIMIZATION_Z3_MATURITIES, log_dir=self.log_dir))
        self.add_optimizer(EarlyOptimizer(DEFAULT_OPTIMIZATION_EARLY_MATURITIES, log_dir=self.log_dir))
        self.analyzer = InstructionAnalyzer(DEFAULT_ANALYZER_MATURITIES, log_dir=self.log_dir)

    def func(self, blk: 'mblock_t', ins: 'minsn_t', optflags: int) ->int:
        self.log_info_on_input(blk, ins)
        try:
            modified = self.optimize(blk, ins)

            if not modified:
                modified = ins.for_all_insns(self.instruction_visitor)

            if modified:
                ins.optimize_solo()

                if blk is not None:
                    blk.mark_lists_dirty()
                    blk.mba.verify(True)

            return modified
        except RuntimeError as e:
            optimizer_logger.error("RuntimeError while optimizing ins {0} with {1}: {2}".format(format_minsn_t(ins), self._last_optimizer_tried, e))
        except D810Exception as e:
            optimizer_logger.error("D810Exception while optimizing ins {0} with {1}: {2}".format(format_minsn_t(ins), self._last_optimizer_tried, e))
        return False

    def reset_rule_usage_statistic(self):
        self.optimizer_usage_info = {}
        for ins_optimizer in self.instruction_optimizers:
            self.optimizer_usage_info[ins_optimizer.name] = 0
            ins_optimizer.reset_rule_usage_statistic()

    def show_rule_usage_statistic(self):
        for optimizer_name, optimizer_nb_match in self.optimizer_usage_info.items():
            if optimizer_nb_match > 0:
                main_logger.info("Instruction optimizer '{0}' has been used {1} times".format(optimizer_name, optimizer_nb_match))
        for ins_optimizer in self.instruction_optimizers:
            ins_optimizer.show_rule_usage_statistic()

    def log_info_on_input(self, blk: mblock_t, ins: minsn_t):
        if blk is None:
            return
        mba: mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            self.current_maturity = mba.maturity
            main_logger.debug("Instruction optimization function called at maturity: {0}".format(maturity_to_string(self.current_maturity)))
            self.analyzer.set_maturity(self.current_maturity)
            self.current_blk_serial = None

            for ins_optimizer in self.instruction_optimizers:
                ins_optimizer.cur_maturity = self.current_maturity

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(mba, self.log_dir, "input_instruction_optimizer")

        if blk.serial != self.current_blk_serial:
            self.current_blk_serial = blk.serial

    def add_optimizer(self, optimizer: InstructionOptimizer):
        self.instruction_optimizers.append(optimizer)
        self.optimizer_usage_info[optimizer.name] = 0

    def add_rule(self, rule: InstructionOptimizationRule):
        # optimizer_log.info("Trying to add rule {0}".format(rule))
        for ins_optimizer in self.instruction_optimizers:
            ins_optimizer.add_rule(rule)
        self.analyzer.add_rule(rule)

    def configure(self, generate_z3_code=False, dump_intermediate_microcode=False):
        self.generate_z3_code = generate_z3_code
        self.dump_intermediate_microcode = dump_intermediate_microcode

    def optimize(self, blk: mblock_t, ins: minsn_t) -> bool:
        # optimizer_log.info("Trying to optimize {0}".format(format_minsn_t(ins)))
        # print("Trying to optimize {0}".format(format_minsn_t(ins)))
        for ins_optimizer in self.instruction_optimizers:
            self._last_optimizer_tried = ins_optimizer
            new_ins = ins_optimizer.get_optimized_instruction(blk, ins)

            if new_ins is not None:
                if not check_ins_mop_size_are_ok(new_ins):
                    if check_ins_mop_size_are_ok(ins):
                        main_logger.error("Invalid optimized instruction: {0} (original was {1})".format(format_minsn_t(new_ins), format_minsn_t(ins)))
                    else:
                        main_logger.error("Invalid original instruction : {0} (original was {1})".format(format_minsn_t(new_ins), format_minsn_t(ins)))
                else:
                    ins.swap(new_ins)
                    self.optimizer_usage_info[ins_optimizer.name] += 1
                    if self.generate_z3_code:
                        try:
                            log_z3_instructions(new_ins, ins)
                        except KeyError:
                            pass
                    return True

        self.analyzer.analyze(blk, ins)
        return False