from d810.optimizers.flow.flattening.generic_dispatcher_collector import GenericDispatcherCollector
from d810.optimizers.flow.flattening.tigress_switch_dispatcher_info import TigressSwitchDispatcherInfo


class TigressSwitchDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = TigressSwitchDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 4
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 4