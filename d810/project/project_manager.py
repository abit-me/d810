import os
from typing import List, Optional
from d810.project.configuration import D810Configuration, ProjectConfiguration
from d810.log.log import D810_LOG_DIR_NAME, main_logger


class ProjectManager:
    _instance: Optional['ProjectManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # 不在 __init__ 中做初始化，避免重复调用
        pass

    def configure(self, d810_config: D810Configuration):
        """配置或重新配置 ProjectManager"""
        self.d810_config = d810_config
        # self.log_dir = self.d810_config.get("log_dir")
        self.log_dir = os.path.join(self.d810_config.get("log_dir"), D810_LOG_DIR_NAME)

        from d810.optimizers.instructions import KNOWN_INS_RULES
        from d810.optimizers.flow import KNOWN_BLK_RULES
        self.known_ins_rules = [x for x in KNOWN_INS_RULES]
        self.known_blk_rules = [x for x in KNOWN_BLK_RULES]

        self.current_project = None
        self.projects: List[ProjectConfiguration] = []
        self.current_project_index = self.d810_config.get("last_project_index")
        self.current_ins_rules = []
        self.current_blk_rules = []

        self.register_default_projects()
        self.load_project(self.current_project_index)

        main_logger.info("ProjectManager configured")
        return self

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_default_projects(self):
        self.projects = []
        for project_configuration_path in self.d810_config.get("configurations"):
            project_configuration = ProjectConfiguration(project_configuration_path, conf_dir=self.d810_config.config_dir)
            project_configuration.load()
            self.projects.append(project_configuration)
        main_logger.debug("Rule configurations loaded: {0}".format(self.projects))

    def add_project(self, config: ProjectConfiguration):
        self.projects.append(config)
        self.d810_config.get("configurations").append(config.path)
        self.d810_config.save()

    def update_project(self, old_config: ProjectConfiguration, new_config: ProjectConfiguration):
        old_config_index = self.projects.index(old_config)
        self.projects[old_config_index] = new_config

    def del_project(self, config: ProjectConfiguration):
        self.projects.remove(config)
        self.d810_config.get("configurations").remove(config.path)
        self.d810_config.save()
        os.remove(config.path)

    @staticmethod
    def dump_ins_rules(ins_rules: List):
        for i, rule in enumerate(ins_rules, 0):
            print(f"{i}. {rule.__class__.__name__}: {rule.description}")

    @staticmethod
    def dump_blk_rules(blk_rules: List):
        for i, rule in enumerate(blk_rules, 0):
            print(f"{i}. {rule.__class__.__name__}: {rule.description}")
            if rule.name == "JumpFixer":
                for jmp_rule in rule.known_rules:
                    print(f"\tjump_fixer->{jmp_rule.__class__.__name__}: {jmp_rule.description}")

    def load_project(self, project_index: int):
        self.current_project_index = project_index
        self.current_project = self.projects[project_index]
        self.current_ins_rules = []
        self.current_blk_rules = []

        # print("known_ins_rules:")
        # self.dump_ins_rules(self.known_ins_rules)
        # print("\nknown_blk_rules:")
        # self.dump_blk_rules(self.known_blk_rules)

        for ins_rule in self.known_ins_rules:
            for rule_conf in self.current_project.ins_rules:
                if ins_rule.name == rule_conf.name:
                    ins_rule.configure(rule_conf.config)
                    ins_rule.set_log_dir(self.log_dir)
                    self.current_ins_rules.append(ins_rule)

        main_logger.debug("Instruction rules configured")
        for blk_rule in self.known_blk_rules:
            for rule_conf in self.current_project.blk_rules:
                if blk_rule.name == rule_conf.name:
                    blk_rule.configure(rule_conf.config)
                    blk_rule.set_log_dir(self.log_dir)
                    self.current_blk_rules.append(blk_rule)

        # print("current_ins_rules:\n")
        # self.dump_ins_rules(self.current_ins_rules)
        # print("current_blk_rules:\n")
        # self.dump_blk_rules(self.current_blk_rules)

        main_logger.debug("Block rules configured")
        main_logger.debug("Project loaded.")


# 模块级便捷访问
def get_project_manager() -> ProjectManager:
    return ProjectManager.get_instance()