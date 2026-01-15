from __future__ import annotations
from d810.error.errors import NotResolvableFatherException
from d810.log.log import unflat_logger
from d810.microcode.microcode_environment import MicroCodeEnvironment
from d810.microcode.microcode_interpreter import MicroCodeInterpreter
from d810.format.hexrays_formatters import format_minsn_t, format_mop_t
from d810.mop.mop_tracker import MopHistory
from ida_hexrays import *


class GenericDispatcherInfo(object):
    def __init__(self, mba: mbl_array_t):
        self.mba = mba
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def reset(self):
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def explore(self, blk: mblock_t) -> bool:
        return False

    def get_shared_internal_blocks(self, other_dispatcher: GenericDispatcherInfo) -> List[mblock_t]:
        my_dispatcher_block_serial = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        other_dispatcher_block_serial = [blk_info.blk.serial for blk_info in other_dispatcher.dispatcher_internal_blocks]
        return [self.mba.get_mblock(blk_serial) for blk_serial in my_dispatcher_block_serial if blk_serial in other_dispatcher_block_serial]

    def is_sub_dispatcher(self, other_dispatcher: GenericDispatcherInfo) -> bool:
        shared_blocks = self.get_shared_internal_blocks(other_dispatcher)
        if (len(shared_blocks) > 0) and (self.entry_block.blk.npred() < other_dispatcher.entry_block.blk.npred()):
            return True
        return False

    def should_emulation_continue(self, cur_blk: mblock_t) -> bool:
        exit_block_serial_list = [exit_block.serial for exit_block in self.dispatcher_exit_blocks]
        if (cur_blk is not None) and (cur_blk.serial not in exit_block_serial_list):
            return True
        return False

    def emulate_dispatcher_with_father_history(self, father_history: MopHistory) -> Tuple[mblock_t, List[minsn_t]]:
        microcode_interpreter = MicroCodeInterpreter()
        microcode_environment = MicroCodeEnvironment()
        dispatcher_input_info = []
        # First, we setup the MicroCodeEnvironment with the state variables (self.entry_block.use_before_def_list)
        # used by the dispatcher
        for initialization_mop in self.entry_block.use_before_def_list:
            # We recover the value of each state variable from the dispatcher father
            initialization_mop_value = father_history.get_mop_constant_value(initialization_mop)
            if initialization_mop_value is None:
                raise NotResolvableFatherException("Can't emulate dispatcher {0} with history {1}".format(self.entry_block.serial, father_history.block_serial_path))
            # We store this value in the MicroCodeEnvironment
            microcode_environment.define(initialization_mop, initialization_mop_value)
            dispatcher_input_info.append("{0} = {1:x}".format(format_mop_t(initialization_mop), initialization_mop_value))

        unflat_logger.info("Executing dispatcher {0} with: {1}".format(self.entry_block.blk.serial, ", ".join(dispatcher_input_info)))

        # Now, we start the emulation of the code at the dispatcher entry block
        instructions_executed = []
        cur_blk = self.entry_block.blk
        cur_ins = cur_blk.head
        # We will continue emulation while we are in one of the dispatcher blocks
        while self.should_emulation_continue(cur_blk):
            unflat_logger.debug("  Executing: {0}.{1}".format(cur_blk.serial, format_minsn_t(cur_ins)))
            # We evaluate the current instruction of the dispatcher to determine
            # which block and instruction should be executed next
            is_ok = microcode_interpreter.eval_instruction(cur_blk, cur_ins, microcode_environment)
            if not is_ok:
                return cur_blk, instructions_executed
            instructions_executed.append(cur_ins)
            cur_blk = microcode_environment.next_blk
            cur_ins = microcode_environment.next_ins
        # We return the first block executed which is not part of the dispatcher
        # and all instructions which have been executed by the dispatcher
        return cur_blk, instructions_executed

    def print_info(self, verbose=False):
        unflat_logger.info("Dispatcher information: ")
        unflat_logger.info("  Entry block: {0}.{1}: ".format(self.entry_block.blk.serial, format_minsn_t(self.entry_block.blk.tail)))
        unflat_logger.info("  Entry block predecessors: {0}: ".format([blk_serial for blk_serial in self.entry_block.blk.predset]))
        unflat_logger.info("    Compared mop: {0} ".format(format_mop_t(self.mop_compared)))
        unflat_logger.info("    Comparison values: {0} ".format(", ".join([hex(x) for x in self.comparison_values])))
        self.entry_block.print_info()
        unflat_logger.info("  Number of internal blocks: {0} ({1})".format(len(self.dispatcher_internal_blocks), [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]))
        if verbose:
            for disp_blk in self.dispatcher_internal_blocks:
                unflat_logger.info("    Internal block: {0}.{1} ".format(disp_blk.blk.serial, format_minsn_t(disp_blk.blk.tail)))
                disp_blk.show_history()
        unflat_logger.info("  Number of Exit blocks: {0} ({1})".format(len(self.dispatcher_exit_blocks), [blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks]))
        if verbose:
            for exit_blk in self.dispatcher_exit_blocks:
                unflat_logger.info("    Exit block: {0}.{1} ".format(exit_blk.blk.serial, format_minsn_t(exit_blk.blk.head)))
                exit_blk.show_history()