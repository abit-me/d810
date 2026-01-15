from d810.log.log import pattern_search_logger
from d810.optimizers.instructions.pattern_matching import PatternMatchingRule
from ida_hexrays import *
from typing import List, Union
from d810.optimizers.instructions.instruction_optimizer import InstructionOptimizer, InstructionOptimizationRule
from d810.ast.ast import minsn_to_ast, AstNode
from d810.format.hexrays_formatters import format_minsn_t


class RulePatternInfo(object):
    def __init__(self, rule, pattern):
        self.rule = rule
        self.pattern = pattern


def signature_generator(ref_sig):
    for i, x in enumerate(ref_sig):
        if x not in ["N", "L"]:
            for sig_suffix in signature_generator(ref_sig[i + 1:]):
                yield ref_sig[:i] + ["L"] + sig_suffix
    yield ref_sig


class PatternStorage(object):
    # The PatternStorage object is used to store patterns associated to rules
    # A PatternStorage contains a dictionary (next_layer_patterns) where:
    #  - keys are the signature of a pattern at a specific depth (i.e. the opcodes, the variable and constant)
    #  - values are PatternStorage object for the next depth
    # Additionally, it stores the rule objects which are resolved for the PatternStorage depth
    def __init__(self, depth=1):
        self.depth = depth
        self.next_layer_patterns = {}
        self.rule_resolved = []

    def add_pattern_for_rule(self, pattern: AstNode, rule: InstructionOptimizationRule):
        layer_signature = self.layer_signature_to_key(pattern.get_depth_signature(self.depth))
        if len(layer_signature.replace(",", "")) == (layer_signature.count("N")):
            self.rule_resolved.append(RulePatternInfo(rule, pattern))
        else:
            if layer_signature not in self.next_layer_patterns.keys():
                self.next_layer_patterns[layer_signature] = PatternStorage(self.depth + 1)
            self.next_layer_patterns[layer_signature].add_pattern_for_rule(pattern, rule)

    @staticmethod
    def layer_signature_to_key(sig: List[str]) -> str:
        return ",".join(sig)

    @staticmethod
    def is_layer_signature_compatible(instruction_signature: str, pattern_signature: str) -> bool:
        if instruction_signature == pattern_signature:
            return True
        instruction_node_list = instruction_signature.split(",")
        pattern_node_list = pattern_signature.split(",")
        for ins_node_sig, pattern_node_sig in zip(instruction_node_list, pattern_node_list):
            if pattern_node_sig not in ["L", "C", "N"] and ins_node_sig != pattern_node_sig:
                return False
        return True

    def get_matching_rule_pattern_info(self, pattern: AstNode):
        pattern_search_logger.info("Searching : {0}".format(pattern))
        return self.explore_one_level(pattern, 1)

    def explore_one_level(self, searched_pattern: AstNode, cur_level: int):
        # We need to check if searched_pattern is in self.next_layer_patterns
        # Easy solution: try/except self.next_layer_patterns[searched_pattern]
        # Problem is that known patterns may not exactly match the microcode instruction, e.g.
        #   -> Pattern layer 3 signature is ["L", "N", "15", "L"]
        #   -> Multiple instruction can match that: ["L", "N", "15", "L"], ["C", "N", "15", "L"], ["C", "N", "15", "13"]
        # This piece of code tries to handles that in a (semi) efficient way
        if len(self.next_layer_patterns) == 0:
            return []
        searched_layer_signature = searched_pattern.get_depth_signature(cur_level)
        nb_possible_signature = 2 ** (len(searched_layer_signature) - searched_layer_signature.count("N") - \
                                searched_layer_signature.count("L"))
        pattern_search_logger.debug("  Layer {0}: {1} -> {2} variations (storage has {3} signature)"
                                    .format(cur_level, searched_layer_signature, nb_possible_signature,
                                            len(self.next_layer_patterns)))
        matched_rule_pattern_info = []
        if nb_possible_signature < len(self.next_layer_patterns):
            pattern_search_logger.debug("  => Using method 1")
            for possible_sig in signature_generator(searched_layer_signature):
                try:
                    test_sig = self.layer_signature_to_key(possible_sig)
                    pattern_storage = self.next_layer_patterns[test_sig]
                    pattern_search_logger.info("    Compatible signature: {0} -> resolved: {1}"
                                               .format(test_sig, pattern_storage.rule_resolved))
                    matched_rule_pattern_info += pattern_storage.rule_resolved
                    matched_rule_pattern_info += pattern_storage.explore_one_level(searched_pattern, cur_level + 1)
                except KeyError:
                    pass
        else:
            pattern_search_logger.debug("  => Using method 2")
            searched_layer_signature_key = self.layer_signature_to_key(searched_layer_signature)
            for test_sig, pattern_storage in self.next_layer_patterns.items():
                if self.is_layer_signature_compatible(searched_layer_signature_key, test_sig):
                    pattern_search_logger.info("    Compatible signature: {0} -> resolved: {1}"
                                               .format(test_sig, pattern_storage.rule_resolved))
                    matched_rule_pattern_info += pattern_storage.rule_resolved
                    matched_rule_pattern_info += pattern_storage.explore_one_level(searched_pattern, cur_level + 1)
        return matched_rule_pattern_info


class PatternOptimizer(InstructionOptimizer):
    # The main idea of PatternOptimizer is to generate/store all possible patterns associated to all known rules in a $
    # dictionary-like object (PatternStorage) when the plugin is loaded.
    # => it means that we generate a very large number of patterns
    #
    # At runtime, we transform the microcode instruction in a list of keys that we search in the PatternStorage object
    # to speed up the checks
    # => we don't want to test all patterns, so we use the PatternStorage object to (quickly) get the patterns
    # which have the same shape as the microcode instruction

    RULE_CLASSES = [PatternMatchingRule]

    def __init__(self, maturities, log_dir=None):
        super().__init__(maturities, log_dir=log_dir)
        self.storage = PatternStorage(depth=1)

    def add_rule(self, rule: InstructionOptimizationRule):
        is_ok = super().add_rule(rule)
        if not is_ok:
            return False
        for pattern in rule.pattern_candidates:
            self.storage.add_pattern_for_rule(pattern, rule)
        return True

    def get_optimized_instruction(self, blk: mblock_t, ins: minsn_t) -> Union[None, minsn_t]:
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        if self.cur_maturity not in self.maturities:
            return None
        tmp = minsn_to_ast(ins)
        if tmp is None:
            return None

        all_matchs = self.storage.get_matching_rule_pattern_info(tmp)
        for rule_pattern_info in all_matchs:
            try:
                new_ins = rule_pattern_info.rule.check_pattern_and_replace(rule_pattern_info.pattern, tmp)
                if new_ins is not None:
                    self.rules_usage_info[rule_pattern_info.rule.name] += 1
                    optimizer_logger.info("Rule {0} matched:".format(rule_pattern_info.rule.name))
                    optimizer_logger.info("  orig: {0}".format(format_minsn_t(ins)))
                    optimizer_logger.info("  new : {0}".format(format_minsn_t(new_ins)))
                    return new_ins
            except RuntimeError as e:
                optimizer_logger.error("Error during rule {0} for instruction {1}: {2}".format(rule_pattern_info.rule, format_minsn_t(ins), e))
        return None


