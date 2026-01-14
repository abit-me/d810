from __future__ import annotations
import logging
from d810.microcode.microcode_environment import MicroCodeEnvironment
from d810.microcode.microcode_interpreter import MicroCodeInterpreter
from d810.format.hexrays_formatters import format_mop_t, format_minsn_t
from d810.helper.hexrays_helpers import get_blk_index
from ida_hexrays import *

logger = logging.getLogger('D810.tracker')


class BlockInfo(object):
    def __init__(self, blk: mblock_t, ins=None):
        self.blk = blk
        self.ins_list = []
        if ins is not None:
            self.ins_list.append(ins)

    def get_copy(self) -> BlockInfo:
        new_block_info = BlockInfo(self.blk)
        new_block_info.ins_list = [x for x in self.ins_list]
        return new_block_info


class MopHistory(object):
    def __init__(self, searched_mop_list: List[mop_t]):
        self.searched_mop_list = [mop_t(x) for x in searched_mop_list]
        self.history = []
        self.unresolved_mop_list = []

        self._mc_interpreter = MicroCodeInterpreter()
        self._mc_initial_environment = MicroCodeEnvironment()
        self._mc_current_environment = self._mc_initial_environment.get_copy()
        self._is_dirty = True

    def add_mop_initial_value(self, mop: mop_t, value: int):
        self._is_dirty = True
        self._mc_initial_environment.define(mop, value)

    def get_copy(self) -> MopHistory:
        new_mop_history = MopHistory(self.searched_mop_list)
        new_mop_history.history = [x.get_copy() for x in self.history]
        new_mop_history.unresolved_mop_list = [x for x in self.unresolved_mop_list]
        new_mop_history._mc_initial_environment = self._mc_initial_environment.get_copy()
        new_mop_history._mc_current_environment = new_mop_history._mc_initial_environment.get_copy()
        return new_mop_history

    def is_resolved(self) -> bool:
        if len(self.unresolved_mop_list) == 0:
            return True
        for x in self.unresolved_mop_list:
            x_value = self._mc_initial_environment.lookup(x, raise_exception=False)
            if x_value is None:
                return False
        return True

    @property
    def block_path(self) -> List[mblock_t]:
        return [blk_info.blk for blk_info in self.history]

    @property
    def block_serial_path(self) -> List[int]:
        return [blk.serial for blk in self.block_path]

    def replace_block_in_path(self, old_blk: mblock_t, new_blk: mblock_t) -> bool:
        blk_index = get_blk_index(old_blk, self.block_path)
        if blk_index > 0:
            self.history[blk_index].blk = new_blk
            self._is_dirty = True
            return True
        else:
            logger.error("replace_block_in_path: should not happen")
            return False

    def insert_block_in_path(self, blk: mblock_t, where_index: int):
        self.history = self.history[:where_index] + [BlockInfo(blk)] + self.history[where_index:]
        self._is_dirty = True

    def insert_ins_in_block(self, blk: mblock_t, ins: minsn_t, before=True):
        blk_index = get_blk_index(blk, self.block_path)
        if blk_index < 0:
            return False
        blk_info = self.history[blk_index]
        if before:
            blk_info.ins_list = [ins] + blk_info.ins_list
        else:
            blk_info.ins_list = blk_info.ins_list + [ins]
        self._is_dirty = True

    def _execute_microcode(self) -> bool:
        if not self._is_dirty:
            return True
        formatted_mop_searched_list = "['" + "', '".join([format_mop_t(x) for x in self.searched_mop_list]) + "']"
        logger.debug("Computing: {0} for path {1}".format(formatted_mop_searched_list, self.block_serial_path))
        self._mc_current_environment = self._mc_initial_environment.get_copy()
        for blk_info in self.history:
            for blk_ins in blk_info.ins_list:
                logger.debug("Executing: {0}.{1}".format(blk_info.blk.serial, format_minsn_t(blk_ins)))
                if not self._mc_interpreter.eval_instruction(blk_info.blk, blk_ins, self._mc_current_environment):
                    self._is_dirty = False
                    return False
        self._is_dirty = False
        return True

    def get_mop_constant_value(self, searched_mop: mop_t) -> Union[None, int]:
        if not self._execute_microcode():
            return None
        return self._mc_interpreter.eval_mop(searched_mop, self._mc_current_environment)

    def print_info(self, detailed_info=False):
        formatted_mop_searched_list = [format_mop_t(x) for x in self.searched_mop_list]
        tmp = ", ".join(["{0}={1}".format(formatted_mop, self.get_mop_constant_value(mop)) for formatted_mop, mop in zip(formatted_mop_searched_list, self.searched_mop_list)])
        logger.info("MopHistory: resolved={0}, path={1}, mops={2}".format(self.is_resolved(), self.block_serial_path, tmp))
        if detailed_info:
            str_mop_list = "['" + "', '".join(formatted_mop_searched_list) + "']"
            if len(self.block_path) == 0:
                logger.info("MopHistory for {0} => nothing".format(str_mop_list))
                return

            end_blk = self.block_path[-1]
            end_ins = end_blk.tail
            if self.history[-1].ins_list:
                end_ins = self.history[-1].ins_list[-1]

            if end_ins:
                logger.info("MopHistory for {0} {1}.{2}".format(str_mop_list, end_blk.serial, format_minsn_t(end_ins)))
            else:
                logger.info("MopHistory for '{0}' {1}.tail".format(str_mop_list, end_blk.serial))
            logger.info("  path {0}".format(self.block_serial_path))
            for blk_info in self.history:
                for blk_ins in blk_info.ins_list:
                    logger.info("   {0}.{1}".format(blk_info.blk.serial, format_minsn_t(blk_ins)))
