from d810.helper.hexrays_helpers import append_mop_if_not_in_list
from d810.optimizers.flow.flattening.generic_dispatcher_block_info import GenericDispatcherBlockInfo
from d810.optimizers.flow.flattening.generic_dispatcher_info import GenericDispatcherInfo
from ida_hexrays import *

class TigressSwitchDispatcherBlockInfo(GenericDispatcherBlockInfo):
    pass


class TigressSwitchDispatcherInfo(GenericDispatcherInfo):
    def explore(self, blk: mblock_t) -> bool:
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return False
        self.mop_compared, mcases = self._get_comparison_info(blk)
        self.entry_block = TigressSwitchDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)
        for possible_values, target_block_serial in zip(mcases.c.values, mcases.c.targets):
            if target_block_serial == self.entry_block.blk.serial:
                continue
            exit_block = TigressSwitchDispatcherBlockInfo(blk.mba.get_mblock(target_block_serial), self.entry_block)
            self.dispatcher_exit_blocks.append(exit_block)
            if len(possible_values) == 0:
                continue
            self.comparison_values.append(possible_values[0])
        return True

    def _get_comparison_info(self, blk: mblock_t) -> Tuple[mop_t, mop_t]:
        # blk.tail must be a jtbl
        if (blk.tail is None) or (blk.tail.opcode != m_jtbl):
            return None, None
        return blk.tail.l, blk.tail.r

    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t) -> bool:
        if (blk.tail is None) or (blk.tail.opcode != m_jtbl):
            return False
        return True