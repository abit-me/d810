from d810.ast.ast import *
import itertools

def get_ast_variations_with_add_sub(opcode, left, right):
    possible_ast = [AstNode(opcode, left, right)]
    if opcode == m_add:
        if isinstance(left, AstNode) and isinstance(right, AstNode):
            if (left.opcode == m_neg) and (right.opcode == m_neg):
                possible_ast.append(AstNode(m_neg, AstNode(m_add, left.left, right.left)))
        if isinstance(right, AstNode) and (right.opcode == m_neg):
            possible_ast.append(AstNode(m_sub, left, right.left))
    return possible_ast


def ast_generator(ast_node, excluded_opcodes=None):
    if not isinstance(ast_node, AstNode):
        return [ast_node]
    res_ast = []
    excluded_opcodes = excluded_opcodes if excluded_opcodes is not None else []
    if ast_node.opcode not in excluded_opcodes:
        if ast_node.opcode in [m_add, m_sub]:
            similar_ast_list = get_similar_opcode_operands(ast_node)
            for similar_ast in similar_ast_list:
                sub_ast_left_list = ast_generator(similar_ast.left, excluded_opcodes=[m_add, m_sub])
                sub_ast_right_list = ast_generator(similar_ast.right, excluded_opcodes=[m_add, m_sub])
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        res_ast += get_ast_variations_with_add_sub(m_add, sub_ast_left, sub_ast_right)
            return res_ast
        if ast_node.opcode in [m_xor, m_or, m_and, m_mul]:
            similar_ast_list = get_similar_opcode_operands(ast_node)
            for similar_ast in similar_ast_list:
                sub_ast_left_list = ast_generator(similar_ast.left, excluded_opcodes=[ast_node.opcode])
                sub_ast_right_list = ast_generator(similar_ast.right, excluded_opcodes=[ast_node.opcode])
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        res_ast += get_ast_variations_with_add_sub(ast_node.opcode, sub_ast_left, sub_ast_right)
            return res_ast
    if ast_node.opcode not in [m_add, m_sub, m_or, m_and, m_mul]:
        excluded_opcodes = []
    nb_operands = 0
    if ast_node.left is not None:
        nb_operands += 1
    if ast_node.right is not None:
        nb_operands += 1
    if nb_operands == 1:
        sub_ast_list = ast_generator(ast_node.left, excluded_opcodes=excluded_opcodes)
        for sub_ast in sub_ast_list:
            res_ast.append(AstNode(ast_node.opcode, sub_ast))
        return res_ast
    if nb_operands == 2:
        sub_ast_left_list = ast_generator(ast_node.left, excluded_opcodes=excluded_opcodes)
        sub_ast_right_list = ast_generator(ast_node.right, excluded_opcodes=excluded_opcodes)
        for sub_ast_left in sub_ast_left_list:
            for sub_ast_right in sub_ast_right_list:
                res_ast += get_ast_variations_with_add_sub(ast_node.opcode, sub_ast_left, sub_ast_right)
        return res_ast
    return []

# AST equivalent pattern generation stuff
# TODO: refactor/clean this


def rec_get_all_binary_subtree_representation(elt_list):
    if len(elt_list) == 1:
        return elt_list
    if len(elt_list) == 2:
        return [elt_list]
    tmp_res = []
    for i in range(1, len(elt_list)):
        left_list = rec_get_all_binary_subtree_representation(elt_list[:i])
        right_list = rec_get_all_binary_subtree_representation(elt_list[i:])
        for l in left_list:
            for r in right_list:
                tmp_res.append([l, r])
    return tmp_res


def rec_get_all_binary_tree_representation(elt_list):
    if len(elt_list) <= 1:
        return elt_list
    tmp = list(itertools.permutations(elt_list))
    tmp2 = []
    for perm_tmp in tmp:
        tmp2 += rec_get_all_binary_subtree_representation(perm_tmp)
    return tmp2


def get_all_binary_tree_representation(all_elt):
    tmp = rec_get_all_binary_tree_representation(all_elt)
    return tmp


def generate_ast(opcode, leafs):
    if isinstance(leafs, AstLeaf):
        return leafs
    if isinstance(leafs, AstNode):
        return leafs
    if len(leafs) == 1:
        return leafs[0]
    if len(leafs) == 2:
        return AstNode(opcode, generate_ast(opcode, leafs[0]), generate_ast(opcode, leafs[1]))
    return None


def get_addition_operands(ast_node):
    if not isinstance(ast_node, AstNode):
        return [ast_node]
    if ast_node.opcode == m_add:
        return get_addition_operands(ast_node.left) + get_addition_operands(ast_node.right)
    elif ast_node.opcode == m_sub:
        tmp = get_addition_operands(ast_node.left)
        for aaa in get_addition_operands(ast_node.right):
            tmp.append(AstNode(m_neg, aaa))
        return tmp
    else:
        return [ast_node]


def get_opcode_operands(ref_opcode, ast_node):
    if not isinstance(ast_node, AstNode):
        return [ast_node]
    if ast_node.opcode == ref_opcode:
        return get_opcode_operands(ref_opcode, ast_node.left) + get_opcode_operands(ref_opcode, ast_node.right)
    else:
        return [ast_node]


def get_similar_opcode_operands(ast_node):
    if ast_node.opcode in [m_add, m_sub]:
        add_elts = get_addition_operands(ast_node)
        all_add_ordering = get_all_binary_tree_representation(add_elts)
        ast_res = []
        for leaf_ordering in all_add_ordering:
            ast_res.append(generate_ast(m_add, leaf_ordering))
        return ast_res
    elif ast_node.opcode in [m_xor, m_or, m_and, m_mul]:
        same_elts = get_opcode_operands(ast_node.opcode, ast_node)
        all_same_ordering = get_all_binary_tree_representation(same_elts)
        ast_res = []
        for leaf_ordering in all_same_ordering:
            ast_res.append(generate_ast(ast_node.opcode, leaf_ordering))
        return ast_res

    else:
        return [ast_node]
