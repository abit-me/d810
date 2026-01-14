from d810.project.module_manager import get_all_subclasses
from d810.optimizers.instructions.analysis.instruction_analysis_rule import InstructionAnalysisRule
from d810.optimizers.instructions.analysis.instruction_analyzer import InstructionAnalyzer
from d810.optimizers.instructions.analysis.example_guessing_rule import *

INSTRUCTION_ANALYSIS_RULES = CHAIN_RULES = [x() for x in get_all_subclasses(InstructionAnalysisRule)]
