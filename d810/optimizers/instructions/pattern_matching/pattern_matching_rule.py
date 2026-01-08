from d810.optimizers.instructions.generic_pattern_rule import GenericPatternRule
from d810.expr.ast import *
from d810.optimizers.instructions.pattern_matching.pattern_matching_util import ast_generator

pattern_matching_logger = logging.getLogger('D810.pattern_matching')

class PatternMatchingRule(GenericPatternRule):
    PATTERN = None
    PATTERNS = None
    FUZZ_PATTERN = True
    REPLACEMENT_PATTERN = None

    def __init__(self):
        super().__init__()
        self.fuzz_pattern = self.FUZZ_PATTERN

    def configure(self, fuzz_pattern=None, **kwargs):
        super().configure(kwargs)
        if fuzz_pattern is not None:
            self.fuzz_pattern = fuzz_pattern
        self._generate_pattern_candidates()
        pattern_matching_logger.debug("Rule {0} configured with {1} patterns".format(self.__class__.__name__, len(self.pattern_candidates)))

    def _generate_pattern_candidates(self):
        self.fuzz_pattern = self.FUZZ_PATTERN
        if self.PATTERN is not None:
            self.PATTERN.reset_mops()
        if not self.fuzz_pattern:
            if self.PATTERN is not None:
                self.pattern_candidates = [self.PATTERN]
                if self.PATTERNS is not None:
                    self.pattern_candidates += [x for x in self.PATTERNS]
            else:
                self.pattern_candidates = [x for x in self.PATTERNS]
        else:
            self.pattern_candidates = ast_generator(self.PATTERN)

    def check_candidate(self, candidate: AstNode):
        return True

    def check_pattern_and_replace(self, candidate_pattern: AstNode, test_ast: AstNode):
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None
        if not self.check_candidate(candidate_pattern):
            return None
        new_instruction = self.get_replacement(candidate_pattern)
        return new_instruction