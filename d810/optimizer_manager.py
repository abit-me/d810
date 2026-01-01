from __future__ import annotations
import os
import json
import logging
import idaapi

import logging

logger = logging.getLogger('D810')

class D810Manager(object):
    def __init__(self, log_dir):
        self.instruction_optimizer_rules = []
        self.instruction_optimizer_config = {}
        self.block_optimizer_rules = []
        self.block_optimizer_config = {}
        self.instruction_optimizer = None
        self.block_optimizer = None
        self.hx_decompiler_hook = None
        self.log_dir = log_dir
        self.config = {}

    def configure(self, **kwargs):
        self.config = kwargs

    def reload(self):
        self.stop()
        logger.debug("Reloading manager...")

        from d810.hexrays_hooks import InstructionOptimizerManager, BlockOptimizerManager, HexraysDecompilationHook

        self.instruction_optimizer = InstructionOptimizerManager(self)
        self.instruction_optimizer.configure(**self.instruction_optimizer_config)
        self.block_optimizer = BlockOptimizerManager(self)
        self.block_optimizer.configure(**self.block_optimizer_config)

        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        self.instruction_optimizer.install()
        self.block_optimizer.install()

        self.hx_decompiler_hook = HexraysDecompilationHook(self)
        self.hx_decompiler_hook.hook()

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = [rule for rule in rules]
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = [rule for rule in rules]
        self.block_optimizer_config = kwargs

    def stop(self):
        if self.instruction_optimizer is not None:
            logger.debug("Removing InstructionOptimizer...")
            self.instruction_optimizer.remove()
            self.instruction_optimizer = None
        if self.block_optimizer is not None:
            logger.debug("Removing ControlFlowFixer...")
            self.block_optimizer.remove()
            self.block_optimizer = None
        if self.hx_decompiler_hook is not None:
            logger.debug("Removing HexraysDecompilationHook...")
            self.hx_decompiler_hook.unhook()
            self.hx_decompiler_hook = None


