import logging
import os

from typing import TYPE_CHECKING
from d810.log import configure_loggers, clear_logs, D810_LOG_DIR_NAME

if TYPE_CHECKING:
    pass

from d810.configuration import D810Configuration
from d810.module_manager import reload_all_modules
from d810.optimizer_manager import OptimizerManager
from d810.project_manager import get_project_manager

# Note that imports are performed directly in the functions so that they are reloaded each time the plugin is restarted
# This allow to load change code/drop new rules without having to reboot IDA
d810_state = None
logger = logging.getLogger('D810')

class StateManager(object):
    def __init__(self):
        # For debugging purposes, to interact with this object from the console
        # Type in IDA Python shell 'from d810.manager import d810_state' to access it
        global d810_state
        d810_state = self
        reload_all_modules()

        self.d810_config = D810Configuration()
        #TO-DO: if [...].get raises an exception because log_dir is not found, handle exception
        self.log_dir = os.path.join(self.d810_config.get("log_dir"), D810_LOG_DIR_NAME)
        self.init_log()
        self.optimizer_manager = OptimizerManager(self.log_dir)
        self.project_manager = get_project_manager()
        self.project_manager.configure(self.d810_config)
        self.project_manager.register_default_projects()
        self.load_project(self.d810_config.get("last_project_index"))

    def load_project(self, project_index: int):
        self.project_manager.load_project(project_index)
        self.optimizer_manager.configure(**self.project_manager.current_project.additional_configuration)

    def init_log(self):
        #TO-DO: if [...].get raises an exception because erase_logs_on_reload is not found, handle exception
        if self.d810_config.get("erase_logs_on_reload"):
            clear_logs(self.log_dir)
        configure_loggers(self.log_dir)

    def start(self):
        print("D-810 ready to deobfuscate...")
        z3_code = self.d810_config.get("generate_z3_code")
        mi_code = self.d810_config.get("dump_intermediate_microcode")

        self.optimizer_manager.configure_instruction_optimizer([rule for rule in self.project_manager.current_ins_rules],
                                                               generate_z3_code=z3_code,
                                                               dump_intermediate_microcode=mi_code,
                                                               **self.project_manager.current_project.additional_configuration)
        self.optimizer_manager.configure_block_optimizer([rule for rule in self.project_manager.current_blk_rules],
                                                         **self.project_manager.current_project.additional_configuration)
        self.optimizer_manager.reload()
        self.d810_config.set("last_project_index", self.project_manager.current_project_index)
        self.d810_config.save()

    def stop(self):
        print("Stopping D-810...")
        self.optimizer_manager.stop()