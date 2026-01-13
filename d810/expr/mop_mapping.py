from d810.hexrays.hexrays_helpers import get_mop_index, AND_TABLE
from ida_hexrays import *

class MopMapping(object):
    def __init__(self):
        self.mops = []
        self.mops_values = []

    def __setitem__(self, mop: mop_t, mop_value: int):
        mop_index = get_mop_index(mop, self.mops)
        mop_value &= AND_TABLE[mop.size]
        if mop_index != -1:
            self.mops_values[mop_index] = mop_value
            return
        self.mops.append(mop)
        self.mops_values.append(mop_value)

    def __getitem__(self, mop: mop_t) -> int:
        mop_index = get_mop_index(mop, self.mops)
        if mop_index == -1:
            raise KeyError
        return self.mops_values[mop_index]

    def __len__(self):
        return len(self.mops)

    def __delitem__(self, mop: mop_t):
        mop_index = get_mop_index(mop, self.mops)
        if mop_index == -1:
            raise KeyError
        del self.mops[mop_index]
        del self.mops_values[mop_index]

    def clear(self):
        self.mops = []
        self.mops_values = []

    def copy(self):
        new_mapping = MopMapping()
        for mop, mop_value in self.items():
            new_mapping[mop] = mop_value
        return new_mapping

    def has_key(self, mop: mop_t):
        mop_index = get_mop_index(mop, self.mops)
        return mop_index != -1

    def keys(self) -> List[mop_t]:
        return self.mops

    def values(self) -> List[int]:
        return self.mops_values

    def items(self):
        return [(x, y) for x, y in zip(self.mops, self.mops_values)]

    def __contains__(self, mop: mop_t):
        return self.has_key(mop)