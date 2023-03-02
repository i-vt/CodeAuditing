import ast

def audit_logical_errors(node):
    errors = []
    if isinstance(node, ast.For):
        if is_range_iterable(node.iter):
            target = node.target
            start, stop, step = get_range_iterable_values(node.iter)
            if not is_valid_for_range(target, start, stop, step):
                errors.append(f"Error: '{target.id}' cannot be used as loop variable in range({start}, {stop}, {step})")
        elif is_valid_list_comprehension(node):
            pass # list comprehensions are valid
        else:
            errors.append("Error: Invalid iterable in for loop")
    elif isinstance(node, ast.While):
        if is_invalid_while_condition(node.test):
            errors.append("Error: Invalid while condition")
    elif isinstance(node, ast.If):
        if is_invalid_if_condition(node.test):
            errors.append("Error: Invalid if condition")
    return errors

def is_range_iterable(iterable):
    if isinstance(iterable, ast.Call) and isinstance(iterable.func, ast.Name) and iterable.func.id == "range":
        return True
    return False

def get_range_iterable_values(iterable):
    args = iterable.args
    keywords = iterable.keywords
    if len(args) == 1:
        return 0, args[0], 1
    elif len(args) == 2:
        return args[0], args[1], 1
    elif len(args) == 3:
        return args[0], args[1], args[2]
    else:
        for keyword in keywords:
            if keyword.arg == "start":
                start = keyword.value.n
            elif keyword.arg == "stop":
                stop = keyword.value.n
            elif keyword.arg == "step":
                step = keyword.value.n
        return start, stop, step

def is_valid_for_range(target, start, stop, step):
    if isinstance(target, ast.Name):
        if isinstance(start, int) and isinstance(stop, int) and isinstance(step, int):
            return True
    return False

def is_valid_list_comprehension(node):
    if isinstance(node, ast.For):
        target = node.target
        iter = node.iter
        if isinstance(iter, ast.Call) and isinstance(iter.func, ast.Name) and iter.func.id == "range":
            start, stop, step = get_range_iterable_values(iter)
            if is_valid_for_range(target, start, stop, step):
                return True
    return False

def is_invalid_while_condition(condition):
    if isinstance(condition, ast.Compare):
        op = condition.ops[0]
        left = condition.left
        right = condition.comparators[0]
        if op.__class__ in (ast.LtE, ast.GtE):
            if is_constant_int(left) and is_constant_int(right):
                return False
    elif isinstance(condition, ast.BoolOp):
        if isinstance(condition.op, ast.And):
            for value in condition.values:
                if is_invalid_while_condition(value):
                    return True
    elif isinstance(condition, ast.UnaryOp):
        if isinstance(condition.op, ast.Not):
            return is_invalid_while_condition(condition.operand)
    return True

import ast

def audit_logical_errors(node):
    errors = []
    if isinstance(node, ast.For):
        if is_range_iterable(node.iter):
            target = node.target
            start, stop, step = get_range_iterable_values(node.iter)
            if not is_valid_for_range(target, start, stop, step):
                errors.append(f"Error: '{target.id}' cannot be used as loop variable in range({start}, {stop}, {step})")
        elif is_valid_list_comprehension(node):
            pass # list comprehensions are valid
        else:
            errors.append("Error: Invalid iterable in for loop")
    elif isinstance(node, ast.While):
        if is_invalid_while_condition(node.test):
            errors.append("Error: Invalid while condition")
    elif isinstance(node, ast.If):
        if is_invalid_if_condition(node.test):
            errors.append("Error: Invalid if condition")
    return errors

def is_range_iterable(iterable):
    if isinstance(iterable, ast.Call) and isinstance(iterable.func, ast.Name) and iterable.func.id == "range":
        return True
    return False

def get_range_iterable_values(iterable):
    args = iterable.args
    keywords = iterable.keywords
    if len(args) == 1:
        return 0, args[0], 1
    elif len(args) == 2:
        return args[0], args[1], 1
    elif len(args) == 3:
        return args[0], args[1], args[2]
    else:
        for keyword in keywords:
            if keyword.arg == "start":
                start = keyword.value.n
            elif keyword.arg == "stop":
                stop = keyword.value.n
            elif keyword.arg == "step":
                step = keyword.value.n
        return start, stop, step

def is_valid_for_range(target, start, stop, step):
    if isinstance(target, ast.Name):
        if isinstance(start, int) and isinstance(stop, int) and isinstance(step, int):
            return True
    return False

def is_valid_list_comprehension(node):
    if isinstance(node, ast.For):
        target = node.target
        iter = node.iter
        if isinstance(iter, ast.Call) and isinstance(iter.func, ast.Name) and iter.func.id == "range":
            start, stop, step = get_range_iterable_values(iter)
            if is_valid_for_range(target, start, stop, step):
                return True
    return False

def is_invalid_while_condition(condition):
    if isinstance(condition, ast.Compare):
        op = condition.ops[0]
        left = condition.left
        right = condition.comparators[0]
        if op.__class__ in (ast.LtE, ast.GtE):
            if is_constant_int(left) and is_constant_int(right):
                return False
    elif isinstance(condition, ast.BoolOp):
        if isinstance(condition.op, ast.And):
            for value in condition.values:
                if is_invalid_while_condition(value):
                    return True
    elif isinstance(condition, ast.UnaryOp):
        if isinstance(condition.op, ast.Not):
            return is_invalid_while_condition(condition.operand)
    return True

def is_invalid_if_condition(condition):
    if isinstance(condition, ast.Compare):
        op = condition.ops[0]
        left = condition.left
        right = condition.comparators[0]
        if op.__class__ in (ast.LtE, ast.GtE):
            if is_constant_int(left) and is_constant_int(right):
                return False
    elif isinstance(condition, ast.BoolOp):
        if isinstance(condition.op, ast.And):
            for value in condition.values:
                if is_invalid_if_condition(value):
                    return True
    elif isinstance(condition, ast.UnaryOp):
        if isinstance(condition.op, ast.Not):
            return is_invalid_if_condition(condition.operand)
    return True
