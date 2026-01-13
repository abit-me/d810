from d810.optimizers.flow.flattening.generic_dispatcher_collector import GenericDispatcherCollector
from d810.optimizers.flow.flattening.ollvm_dispatcher_info import OllvmDispatcherInfo


class OllvmDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = OllvmDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 3
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2