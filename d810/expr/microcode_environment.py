from __future__ import annotations
import logging
from typing import Dict

from d810.expr.mop_mapping import MopMapping
from idaapi import getseg, get_qword, SEGPERM_WRITE
from ida_hexrays import *
from d810.expr.arithmetic_util import unsigned_to_signed, signed_to_unsigned, get_add_cf, get_add_of, get_sub_of, ror, get_parity_flag
from d810.hexrays.hexrays_helpers import equal_mops_ignore_size, get_mop_index, AND_TABLE, CONTROL_FLOW_OPCODES, CONDITIONAL_JUMP_OPCODES
from d810.hexrays.hexrays_formatters import format_minsn_t, format_mop_t, mop_type_to_string, opcode_to_string
from d810.hexrays.cfg_util import get_block_serials_by_address
from d810.errors import EmulationException, EmulationIndirectJumpException, UnresolvedMopException, WritableMemoryReadException

emulator_log = logging.getLogger('D810.emulator')


class MicroCodeEnvironment(object):
    def __init__(self, parent: Union[None, MicroCodeEnvironment] = None):
        self.parent = parent
        self.mop_r_record = MopMapping()
        self.mop_S_record = MopMapping()

        self.cur_blk = None
        self.cur_ins = None
        self.next_blk = None
        self.next_ins = None

    def items(self):
        return [x for x in self.mop_r_record.items() + self.mop_S_record.items()]

    def get_copy(self, copy_parent=True) -> MicroCodeEnvironment:
        parent_copy = self.parent
        if parent_copy is not None and copy_parent:
            parent_copy = self.parent.get_copy(copy_parent=True)
        new_env = MicroCodeEnvironment(parent_copy)
        for mop, mop_value in self.mop_r_record.items():
            new_env.define(mop, mop_value)
        for mop, mop_value in self.mop_S_record.items():
            new_env.define(mop, mop_value)
        new_env.cur_blk = self.cur_blk
        new_env.cur_ins = self.cur_ins
        new_env.next_blk = self.next_blk
        new_env.next_ins = self.next_ins
        return new_env

    def set_cur_flow(self, cur_blk: mblock_t, cur_ins: minsn_t):
        self.cur_blk = cur_blk
        self.cur_ins = cur_ins
        self.next_blk = cur_blk
        if self.cur_ins is None:
            self.next_blk = self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1)
            self.next_ins = self.next_blk.head
        else:
            self.next_ins = self.cur_ins.next
            if self.next_ins is None:
                self.next_blk = self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1)
                self.next_ins = self.next_blk.head
        emulator_log.debug(
            "Setting next block {0} and next ins {1}".format(self.next_blk.serial, format_minsn_t(self.next_ins)))

    def set_next_flow(self, next_blk: mblock_t, next_ins: minsn_t):
        self.next_blk = next_blk
        self.next_ins = next_ins

    def define(self, mop: mblock_t, value: int) -> int:
        if mop.t == mop_r:
            self.mop_r_record[mop] = value
            return value
        elif mop.t == mop_S:
            self.mop_S_record[mop] = value
            return value
        raise EmulationException("Defining an unsupported mop type '{0}': '{1}'"
                                 .format(mop_type_to_string(mop.t), format_mop_t(mop)))

    def _lookup_mop(self, searched_mop: mop_t, mop_value_dict: Dict[mop_t, int], new_mop_value: Union[None, int] = None,
                    auto_define=True, raise_exception=True) -> int:
        for known_mop, mop_value in mop_value_dict.items():
            if equal_mops_ignore_size(searched_mop, known_mop):
                if new_mop_value is not None:
                    mop_value_dict[searched_mop] = new_mop_value
                    return new_mop_value
                return mop_value
        if (new_mop_value is not None) and auto_define:
            self.define(searched_mop, new_mop_value)
            return new_mop_value
        if raise_exception:
            raise EmulationException("Variable '{0}' is not defined".format(format_mop_t(searched_mop)))
        else:
            return None

    def lookup(self, mop: mop_t, raise_exception=True) -> int:
        if mop.t == mop_r:
            return self._lookup_mop(mop, self.mop_r_record, raise_exception=raise_exception)
        elif mop.t == mop_S:
            return self._lookup_mop(mop, self.mop_S_record, raise_exception=raise_exception)

    def assign(self, mop: mop_t, value: int, auto_define=True) -> int:
        if mop.t == mop_r:
            return self._lookup_mop(mop, self.mop_r_record, value, auto_define)
        elif mop.t == mop_S:
            return self._lookup_mop(mop, self.mop_S_record, value, auto_define)
        raise EmulationException("Assigning an unsupported mop type '{0}': '{1}'"
                                 .format(mop_type_to_string(mop.t), format_mop_t(mop)))
