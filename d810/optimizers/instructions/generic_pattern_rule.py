from d810.expr.ast import *
from d810.optimizers.instructions.instruction_optimization_rule import InstructionOptimizationRule


class GenericPatternRule(InstructionOptimizationRule):
    PATTERN = None
    PATTERNS = None
    REPLACEMENT_PATTERN = None

    def __init__(self):
        super().__init__()
        self.pattern_candidates = [self.PATTERN]
        if self.PATTERNS is not None:
            self.pattern_candidates += self.PATTERNS

    def check_candidate(self, candidate: AstNode):
        # Perform rule specific checks
        return False

    def get_valid_candidates(self, instruction: minsn_t, stop_early=True):
        valid_candidates = []
        tmp = minsn_to_ast(instruction)
        if tmp is None:
            return []
        for candidate_pattern in self.pattern_candidates:
            if not candidate_pattern.check_pattern_and_copy_mops(tmp):
                continue
            if not self.check_candidate(candidate_pattern):
                continue
            valid_candidates.append(candidate_pattern)
            if stop_early:
                return valid_candidates
        return []

    def get_replacement(self, candidate: AstNode):
        is_ok = self.REPLACEMENT_PATTERN.update_leafs_mop(candidate)
        if not is_ok:
            return None
        new_ins = self.REPLACEMENT_PATTERN.create_minsn(candidate.ea, candidate.dst_mop)
        return new_ins

    def check_and_replace(self, blk: mblock_t, instruction: minsn_t):
        valid_candidates = self.get_valid_candidates(instruction, stop_early=True)
        if len(valid_candidates) == 0:
            return None
        new_instruction = self.get_replacement(valid_candidates[0])
        return new_instruction

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        if (self.PATTERN is None) or (self.REPLACEMENT_PATTERN is None):
            return ""
        self.PATTERN.reset_mops()
        self.REPLACEMENT_PATTERN.reset_mops()
        return "{0} => {1}".format(self.PATTERN, self.REPLACEMENT_PATTERN)