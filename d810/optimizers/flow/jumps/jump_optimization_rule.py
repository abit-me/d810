from d810.format.hexrays_formatters import opcode_to_string
from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizationRule
from d810.ast.ast import AstNode
from d810.optimizers.instructions.pattern_matching.pattern_matching_util import ast_generator
from ida_hexrays import *


class JumpOptimizationRule(InstructionOptimizationRule):
    ORIGINAL_JUMP_OPCODES = []
    LEFT_PATTERN = None
    RIGHT_PATTERN = None

    REPLACEMENT_OPCODE = None
    REPLACEMENT_LEFT_PATTERN = None
    REPLACEMENT_RIGHT_PATTERN = None

    FUZZ_PATTERNS = True

    def __init__(self):
        super().__init__()
        self.fuzz_patterns = self.FUZZ_PATTERNS
        self.left_pattern_candidates = []
        self.right_pattern_candidates = []
        self.jump_original_block_serial = None
        self.direct_block_serial = None
        self.jump_replacement_block_serial = None

    def configure(self, fuzz_pattern=None, **kwargs):
        super().configure(kwargs)
        if fuzz_pattern is not None:
            self.fuzz_patterns = fuzz_pattern
        self._generate_pattern_candidates()

    def _generate_pattern_candidates(self):
        self.fuzz_patterns = self.FUZZ_PATTERNS
        if self.LEFT_PATTERN is not None:
            self.LEFT_PATTERN.reset_mops()
            if not self.fuzz_patterns:
                self.left_pattern_candidates = [self.LEFT_PATTERN]
            else:
                self.left_pattern_candidates = ast_generator(self.LEFT_PATTERN)
        if self.RIGHT_PATTERN is not None:
            self.RIGHT_PATTERN.reset_mops()
            if not self.fuzz_patterns:
                self.right_pattern_candidates = [self.RIGHT_PATTERN]
            else:
                self.right_pattern_candidates = ast_generator(self.RIGHT_PATTERN)

    def check_candidate(self, opcode, left_candidate: AstNode, right_candidate: AstNode):
        return False

    def get_valid_candidates(self, instruction: minsn_t, left_ast: AstNode, right_ast: AstNode, stop_early=True):
        valid_candidates = []
        if left_ast is None or right_ast is None:
            return []

        for left_candidate_pattern in self.left_pattern_candidates:
            if not left_candidate_pattern.check_pattern_and_copy_mops(left_ast):
                continue
            for right_candidate_pattern in self.right_pattern_candidates:
                if not right_candidate_pattern.check_pattern_and_copy_mops(right_ast):
                    continue
                if not self.check_candidate(instruction.opcode, left_candidate_pattern, right_candidate_pattern):
                    continue
                valid_candidates.append([left_candidate_pattern, right_candidate_pattern])
                if stop_early:
                    return valid_candidates
        return []

    def check_pattern_and_replace(self, blk: mblock_t, instruction: minsn_t, left_ast: AstNode, right_ast: AstNode):
        if instruction.opcode not in self.ORIGINAL_JUMP_OPCODES:
            return None
        self.jump_original_block_serial = instruction.d.b
        self.direct_block_serial = blk.serial + 1
        self.jump_replacement_block_serial = None
        valid_candidates = self.get_valid_candidates(instruction, left_ast, right_ast, stop_early=True)
        if len(valid_candidates) == 0:
            return None
        if self.jump_original_block_serial is None:
            self.jump_replacement_block_serial = self.jump_original_block_serial
        left_candidate, right_candidate = valid_candidates[0]
        new_ins = self.get_replacement(instruction, left_candidate, right_candidate)
        return new_ins

    def get_replacement(self, original_ins: minsn_t, left_candidate: AstNode, right_candidate: AstNode):
        new_left_mop = None
        new_right_mop = None
        new_dst_mop = None

        if self.jump_original_block_serial is not None:
            new_dst_mop = mop_t()
            new_dst_mop.make_blkref(self.jump_replacement_block_serial)

        if self.REPLACEMENT_LEFT_PATTERN is not None:
            is_ok = self.REPLACEMENT_LEFT_PATTERN.update_leafs_mop(left_candidate, right_candidate)
            if not is_ok:
                return None
            new_left_mop = self.REPLACEMENT_LEFT_PATTERN.create_mop(original_ins.ea)
        if self.REPLACEMENT_RIGHT_PATTERN is not None:
            is_ok = self.REPLACEMENT_RIGHT_PATTERN.update_leafs_mop(left_candidate, right_candidate)
            if not is_ok:
                return None
            new_right_mop = self.REPLACEMENT_RIGHT_PATTERN.create_mop(original_ins.ea)

        new_ins = self.create_new_ins(original_ins, new_left_mop, new_right_mop, new_dst_mop)
        return new_ins

    def create_new_ins(self, original_ins: minsn_t, new_left_mop: mop_t, new_right_mop: Union[None, mop_t] = None, new_dst_mop: Union[None, mop_t] = None) -> minsn_t:
        new_ins = minsn_t(original_ins)
        new_ins.opcode = self.REPLACEMENT_OPCODE
        if self.REPLACEMENT_OPCODE == m_goto:
            new_ins.l = new_dst_mop
            new_ins.r.erase()
            new_ins.d.erase()
            return new_ins
        new_ins.l = new_left_mop
        if new_right_mop is not None:
            new_ins.r = new_right_mop
        if new_dst_mop is not None:
            new_ins.d = new_dst_mop
        return new_ins

    @property
    def description(self):
        if self.LEFT_PATTERN is None or self.RIGHT_PATTERN is None:
            return ""

        self.LEFT_PATTERN.reset_mops()
        self.RIGHT_PATTERN.reset_mops()
        orig_jmp_codes = ",".join([opcode_to_string(x) for x in self.ORIGINAL_JUMP_OPCODES])
        return "{0}: {1}, {2}".format(orig_jmp_codes, self.LEFT_PATTERN, self.RIGHT_PATTERN)