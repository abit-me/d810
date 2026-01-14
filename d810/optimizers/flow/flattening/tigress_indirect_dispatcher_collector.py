from d810.optimizers.flow.flattening.generic_dispatcher_collector import GenericDispatcherCollector
from d810.optimizers.flow.flattening.tigress_indirect_dispatcher_info import TigressIndirectDispatcherInfo


class TigressIndirectDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = TigressIndirectDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 0