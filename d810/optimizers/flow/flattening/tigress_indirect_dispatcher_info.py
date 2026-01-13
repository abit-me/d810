from d810.hexrays.hexrays_helpers import append_mop_if_not_in_list
from d810.optimizers.flow.flattening.generic_dispatcher_block_info import GenericDispatcherBlockInfo
from d810.optimizers.flow.flattening.generic_dispatcher_info import GenericDispatcherInfo
from ida_hexrays import *

class TigressIndirectDispatcherBlockInfo(GenericDispatcherBlockInfo):
    pass

class TigressIndirectDispatcherInfo(GenericDispatcherInfo):
    def explore(self, blk: mblock_t) -> bool:
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return False
        self.mop_compared = self._get_comparison_info(blk)
        self.entry_block = TigressIndirectDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        self.dispatcher_exit_blocks = []
        self.comparison_values = []
        return True

    def _get_comparison_info(self, blk: mblock_t) -> Tuple[mop_t, mop_t]:
        if (blk.tail is None) or (blk.tail.opcode != m_ijmp):
            return None, None
        return blk.tail.l

    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t) -> bool:
        if (blk.tail is None) or (blk.tail.opcode != m_ijmp):
            return False
        return True

    def should_emulation_continue(self, cur_blk: mblock_t):
        if (cur_blk is not None) and (cur_blk.serial == self.entry_block.serial):
            return True
        return False
