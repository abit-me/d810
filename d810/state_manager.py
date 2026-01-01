import logging
import os
from typing import List

from d810.conf import D810Configuration, ProjectConfiguration
from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from d810.conf import D810Configuration, ProjectConfiguration

from d810.module_manager import reload_all_modules
from d810.manager import D810Manager
# Note that imports are performed directly in the functions so that they are reloaded each time the plugin is restarted
# This allow to load change code/drop new rules without having to reboot IDA
d810_state = None

D810_LOG_DIR_NAME = "d810_logs"
logger = logging.getLogger('D810')

class D810State(object):
    def __init__(self, d810_config: D810Configuration):
        # For debugging purposes, to interact with this object from the console
        # Type in IDA Python shell 'from d810.manager import d810_state' to access it
        global d810_state
        d810_state = self
        reload_all_modules()

        self.d810_config = d810_config
        self.log_dir = os.path.join(self.d810_config.get("log_dir"), D810_LOG_DIR_NAME)
        self.d810_manager = D810Manager(self.log_dir)

        from d810.project_manager import ProjectManager
        self.project_manager = ProjectManager(self.d810_config)
        self.project_manager.register_default_projects()
        self.load_project(self.d810_config.get("last_project_index"))

        self.gui = None

    def load_project(self, project_index: int):
        self.project_manager.load_project(project_index)
        self.d810_manager.configure(**self.project_manager.current_project.additional_configuration)

    def add_project(self, config: ProjectConfiguration):
        self.project_manager.add_project(config)

    def update_project(self, old_config: ProjectConfiguration, new_config: ProjectConfiguration):
        self.project_manager.update_project(old_config, new_config)

    def del_project(self, config: ProjectConfiguration):
        self.project_manager.del_project(config)

    def current_ins_rules(self) -> List:
        return self.project_manager.current_ins_rules

    def current_blk_rules(self) -> List:
        return self.project_manager.current_blk_rules

    def current_project_index(self) -> int:
        return self.project_manager.current_project_index

    def current_project(self) -> ProjectConfiguration:
        return self.project_manager.current_project



    def start_d810(self):
        print("D-810 ready to deobfuscate...")
        z3_code = self.d810_config.get("generate_z3_code")
        mi_code = self.d810_config.get("dump_intermediate_microcode")

        self.d810_manager.configure_instruction_optimizer([rule for rule in self.get_current_ins_rules()],
                                                          generate_z3_code=z3_code,
                                                          dump_intermediate_microcode=mi_code,
                                                          **self.get_current_project().additional_configuration)
        self.d810_manager.configure_block_optimizer([rule for rule in self.get_current_blk_rules()],
                                                    **self.get_current_project().additional_configuration)
        self.d810_manager.reload()
        self.d810_config.set("last_project_index", self.get_current_project_index())
        self.d810_config.save()

    def stop_d810(self):
        print("Stopping D-810...")
        self.d810_manager.stop()

    def start_plugin(self):
        from d810.ida_ui import D810GUI
        self.gui = D810GUI(self)
        self.gui.show_windows()

    def stop_plugin(self):
        self.d810_manager.stop()
        if self.gui:
            self.gui.term()
            self.gui = None