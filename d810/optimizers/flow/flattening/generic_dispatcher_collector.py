from __future__ import annotations
import logging
from d810.hexrays.hexrays_formatters import format_minsn_t, format_mop_list
from d810.hexrays.hexrays_helpers import append_mop_if_not_in_list, get_mop_index, CONDITIONAL_JUMP_OPCODES, \
    extract_num_mop
from d810.hexrays.hexrays_hooks import InstructionDefUseCollector
from d810.hexrays.tracker import remove_segment_registers
from d810.optimizers.flow.flattening.generic_dispatcher_info import GenericDispatcherInfo
from ida_hexrays import *

unflat_logger = logging.getLogger('D810.unflat')

class GenericDispatcherCollector(minsn_visitor_t):
    DISPATCHER_CLASS = GenericDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2

    def __init__(self):
        super().__init__()
        self.dispatcher_list = []
        self.explored_blk_serials = []
        self.dispatcher_min_internal_block = self.DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK
        self.dispatcher_min_exit_block = self.DEFAULT_DISPATCHER_MIN_EXIT_BLOCK
        self.dispatcher_min_comparison_value = self.DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE

    def configure(self, kwargs):
        if "min_dispatcher_internal_block" in kwargs.keys():
            self.dispatcher_min_internal_block = kwargs["min_dispatcher_internal_block"]
        if "min_dispatcher_exit_block" in kwargs.keys():
            self.dispatcher_min_exit_block = kwargs["min_dispatcher_exit_block"]
        if "min_dispatcher_comparison_value" in kwargs.keys():
            self.dispatcher_min_comparison_value = kwargs["min_dispatcher_comparison_value"]

    def specific_checks(self, disp_info: GenericDispatcherInfo) -> bool:
        unflat_logger.debug("DispatcherInfo {0} : {1} internals, {2} exits, {3} comparison"
                            .format(self.blk.serial, len(disp_info.dispatcher_internal_blocks),
                                    len(disp_info.dispatcher_exit_blocks), len(set(disp_info.comparison_values))))
        if len(disp_info.dispatcher_internal_blocks) < self.dispatcher_min_internal_block:
            return False
        if len(disp_info.dispatcher_exit_blocks) < self.dispatcher_min_exit_block:
            return False
        if len(set(disp_info.comparison_values)) < self.dispatcher_min_comparison_value:
            return False
        self.dispatcher_list.append(disp_info)
        return True

    def visit_minsn(self):
        if self.blk.serial in self.explored_blk_serials:
            return 0
        self.explored_blk_serials.append(self.blk.serial)
        disp_info = self.DISPATCHER_CLASS(self.blk.mba)
        is_good_candidate = disp_info.explore(self.blk)
        if not is_good_candidate:
            return 0
        if not self.specific_checks(disp_info):
            return 0
        self.dispatcher_list.append(disp_info)
        return 0

    def remove_sub_dispatchers(self):
        main_dispatcher_list = []
        for dispatcher_1 in self.dispatcher_list:
            is_dispatcher_1_sub_dispatcher = False
            for dispatcher_2 in self.dispatcher_list:
                if dispatcher_1.is_sub_dispatcher(dispatcher_2):
                    is_dispatcher_1_sub_dispatcher = True
                    break
            if not is_dispatcher_1_sub_dispatcher:
                main_dispatcher_list.append(dispatcher_1)
        self.dispatcher_list = [x for x in main_dispatcher_list]

    def reset(self):
        self.dispatcher_list = []
        self.explored_blk_serials = []

    def get_dispatcher_list(self) -> List[GenericDispatcherInfo]:
        self.remove_sub_dispatchers()
        return self.dispatcher_list