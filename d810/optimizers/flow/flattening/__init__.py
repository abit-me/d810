from d810.optimizers.flow.flattening.ollvm_unflattener import OllvmUnflattener
from d810.optimizers.flow.flattening.tigress_switch_unflattener import TigressSwitchUnflattener
from d810.optimizers.flow.flattening.tigress_indirect_unflattener import TigressIndirectUnflattener
from d810.optimizers.flow.flattening.fake_jump_unflattener import FakeJumpUnflattener
from d810.optimizers.flow.flattening.fix_pred_cond_jump_block import FixPredecessorOfConditionalJumpBlock

UNFLATTENING_BLK_RULES = [OllvmUnflattener(), TigressSwitchUnflattener(), TigressIndirectUnflattener(), FakeJumpUnflattener(),
                          FixPredecessorOfConditionalJumpBlock()]
