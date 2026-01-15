from __future__ import annotations
from d810.error.errors import NotDuplicableFatherException, NotResolvableFatherException
from d810.helper.cfg_util import ensure_child_has_an_unconditional_father, create_block, change_1way_block_successor, ensure_last_block_is_goto, mba_deep_cleaning
from d810.format.hexrays_formatters import format_minsn_t, format_mop_list, dump_microcode_for_debug, format_mop_t
from d810.helper.hexrays_helpers import CONTROL_FLOW_OPCODES
from d810.log.log import unflat_logger
from d810.mop.mop_tracker import MopHistory, MopTracker, duplicate_histories
from d810.optimizers.flow.flattening.generic_dispatcher_block_info import GenericDispatcherBlockInfo
from d810.optimizers.flow.flattening.generic_dispatcher_collector import GenericDispatcherCollector
from d810.optimizers.flow.flattening.generic_dispatcher_info import GenericDispatcherInfo
from d810.optimizers.flow.flattening.generic_unflattening_rule import GenericUnflatteningRule
from d810.optimizers.flow.flattening.unflattener_util import get_all_possibles_values, check_if_all_values_are_found
from ida_hexrays import *



class GenericDispatcherUnflatteningRule(GenericUnflatteningRule):
    DISPATCHER_COLLECTOR_CLASS = GenericDispatcherCollector
    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5

    def __init__(self):
        super().__init__()
        self.dispatcher_collector = self.DISPATCHER_COLLECTOR_CLASS()
        self.dispatcher_list = []
        self.max_duplication_passes = self.DEFAULT_MAX_DUPLICATION_PASSES
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.non_significant_changes = 0

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if not super().check_if_rule_should_be_used(blk):
            return False
        if (self.cur_maturity_pass >= 1) and (self.last_pass_nb_patch_done == 0):
            return False
        if (self.max_passes is not None) and (self.cur_maturity_pass >= self.max_passes):
            return False
        return True

    def configure(self, kwargs):
        super().configure(kwargs)
        if "max_passes" in self.config.keys():
            self.max_passes = self.config["max_passes"]
        if "max_duplication_passes" in self.config.keys():
            self.max_duplication_passes = self.config["max_duplication_passes"]
        self.dispatcher_collector.configure(kwargs)

    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.reset()
        self.mba.for_all_topinsns(self.dispatcher_collector)
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def ensure_all_dispatcher_fathers_are_direct(self) -> int:
        nb_change = 0
        for dispatcher_info in self.dispatcher_list:
            nb_change += self.ensure_dispatcher_fathers_are_direct(dispatcher_info)
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:
                nb_change += ensure_child_has_an_unconditional_father(dispatcher_father, dispatcher_info.entry_block.blk)
        return nb_change

    def ensure_dispatcher_fathers_are_direct(self, dispatcher_info: GenericDispatcherInfo) -> int:
        nb_change = 0
        dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
        for dispatcher_father in dispatcher_father_list:
            nb_change += ensure_child_has_an_unconditional_father(dispatcher_father, dispatcher_info.entry_block.blk)
        return nb_change

    def register_initialization_variables(self, mop_tracker):
        pass

    def get_dispatcher_father_histories(self, dispatcher_father: mblock_t, dispatcher_entry_block: GenericDispatcherBlockInfo) -> List[MopHistory]:
        father_tracker = MopTracker(dispatcher_entry_block.use_before_def_list, max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK, max_path=self.MOP_TRACKER_MAX_NB_PATH)
        father_tracker.reset()
        self.register_initialization_variables(father_tracker)
        father_histories = father_tracker.search_backward(dispatcher_father, None)
        return father_histories

    def check_if_histories_are_resolved(self, mop_histories: List[MopHistory]) -> bool:
        return all([mop_history.is_resolved() for mop_history in mop_histories])

    def ensure_dispatcher_father_is_resolvable(self, dispatcher_father: mblock_t, dispatcher_entry_block: GenericDispatcherBlockInfo) -> int:
        father_histories = self.get_dispatcher_father_histories(dispatcher_father, dispatcher_entry_block)
        father_histories_cst = get_all_possibles_values(father_histories, dispatcher_entry_block.use_before_def_list, verbose=False)
        father_is_resolvable = self.check_if_histories_are_resolved(father_histories)
        if not father_is_resolvable:
            raise NotDuplicableFatherException("Dispatcher {0} predecessor {1} is not duplicable: {2}".format(dispatcher_entry_block.serial, dispatcher_father.serial, father_histories_cst))
        for father_history_cst in father_histories_cst:
            if None in father_history_cst:
                raise NotDuplicableFatherException("Dispatcher {0} predecessor {1} has None value: {2}".format(dispatcher_entry_block.serial, dispatcher_father.serial, father_histories_cst))

        unflat_logger.info("Dispatcher {0} predecessor {1} is resolvable: {2}".format(dispatcher_entry_block.serial, dispatcher_father.serial, father_histories_cst))
        nb_duplication, nb_change = duplicate_histories(father_histories, max_nb_pass=self.max_duplication_passes)
        unflat_logger.info("Dispatcher {0} predecessor {1} duplication: {2} blocks created, {3} changes made".format(dispatcher_entry_block.serial, dispatcher_father.serial, nb_duplication, nb_change))
        return nb_duplication + nb_change

    def resolve_dispatcher_father(self, dispatcher_father: mblock_t, dispatcher_info: GenericDispatcherInfo) -> int:
        dispatcher_father_histories = self.get_dispatcher_father_histories(dispatcher_father, dispatcher_info.entry_block)
        father_is_resolvable = self.check_if_histories_are_resolved(dispatcher_father_histories)
        if not father_is_resolvable:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))
        mop_searched_values_list = get_all_possibles_values(dispatcher_father_histories, dispatcher_info.entry_block.use_before_def_list, verbose=False)
        all_values_found = check_if_all_values_are_found(mop_searched_values_list)
        if not all_values_found:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))

        ref_mop_searched_values = mop_searched_values_list[0]
        for tmp_mop_searched_values in mop_searched_values_list:
            if tmp_mop_searched_values != ref_mop_searched_values:
                raise NotResolvableFatherException("Dispatcher {0} predecessor {1} is not resolvable: {2}".format(dispatcher_info.entry_block.serial, dispatcher_father.serial, mop_searched_values_list))

        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(dispatcher_father_histories[0])
        if target_blk is not None:
            unflat_logger.debug("Unflattening graph: Making {0} goto {1}".format(dispatcher_father.serial, target_blk.serial))
            ins_to_copy = [ins for ins in disp_ins if ((ins is not None) and (ins.opcode not in CONTROL_FLOW_OPCODES))]
            if len(ins_to_copy) > 0:
                unflat_logger.info("Instruction copied: {0}: {1}".format(len(ins_to_copy), ", ".join([format_minsn_t(ins_copied) for ins_copied in ins_to_copy])))
                dispatcher_side_effect_blk = create_block(self.mba.get_mblock(self.mba.qty - 2), ins_to_copy, is_0_way=(target_blk.type == BLT_0WAY))
                change_1way_block_successor(dispatcher_father, dispatcher_side_effect_blk.serial)
                change_1way_block_successor(dispatcher_side_effect_blk, target_blk.serial)
            else:
                change_1way_block_successor(dispatcher_father, target_blk.serial)
            return 2

        raise NotResolvableFatherException("Can't fix block {0}: no block for key: {1}".format(dispatcher_father.serial, mop_searched_values_list))

    def remove_flattening(self) -> int:
        total_nb_change = 0
        self.non_significant_changes = ensure_last_block_is_goto(self.mba)
        self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()
        for dispatcher_info in self.dispatcher_list:
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_before_duplication".format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
            unflat_logger.info("Searching dispatcher for entry block {0} {1} ->  with variables ({2})...".format(dispatcher_info.entry_block.serial, format_mop_t(dispatcher_info.mop_compared), format_mop_list(dispatcher_info.entry_block.use_before_def_list)))
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:
                try:
                    total_nb_change += self.ensure_dispatcher_father_is_resolvable(dispatcher_father, dispatcher_info.entry_block)
                except NotDuplicableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_duplication".format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
            # During the previous step we changed dispatcher entry block fathers, so we need to reload them
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            nb_flattened_branches = 0
            for dispatcher_father in dispatcher_father_list:
                try:
                    nb_flattened_branches += self.resolve_dispatcher_father(dispatcher_father, dispatcher_info)
                except NotResolvableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_unflattening".format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))

        unflat_logger.info("Unflattening removed {0} branch".format(nb_flattened_branches))
        total_nb_change += nb_flattened_branches
        return total_nb_change

    def optimize(self, blk: mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = 0
        unflat_logger.info("Unflattening at maturity {0} pass {1}".format(self.cur_maturity, self.cur_maturity_pass))
        dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_start".format(self.cur_maturity_pass))
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            unflat_logger.info("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        else:
            unflat_logger.info("Unflattening: {0} dispatcher(s) found".format(len(self.dispatcher_list)))
            for dispatcher_info in self.dispatcher_list:
                dispatcher_info.print_info()
            self.last_pass_nb_patch_done = self.remove_flattening()
        unflat_logger.info("Unflattening at maturity {0} pass {1}: {2} changes".format(self.cur_maturity, self.cur_maturity_pass, self.last_pass_nb_patch_done))
        nb_clean = mba_deep_cleaning(self.mba, False)
        dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_after_cleaning".format(self.cur_maturity_pass))
        if self.last_pass_nb_patch_done + nb_clean + self.non_significant_changes > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
        self.mba.verify(True)
        return self.last_pass_nb_patch_done