import ast

# Define a function to check for output validation
def audit_output_validation(node):
    # Check for function definitions
    if isinstance(node, ast.FunctionDef):
        # Check for return statements
        for stmt in node.body:
            if isinstance(stmt, ast.Return):
                # Check for annotated returns
                if stmt.value and stmt.value.annotation:
                    # Check for built-in types
                    if isinstance(stmt.value.annotation, ast.Name) and stmt.value.annotation.id in {"int", "float", "str", "bool"}:
                        # Check for value range validation
                        if isinstance(stmt.value, ast.Constant):
                            validate_constant(stmt.value, stmt.value.annotation.id, node.name)
                        elif isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Add):
                            for arg in (stmt.value.left, stmt.value.right):
                                if isinstance(arg, ast.Constant):
                                    validate_constant(arg, stmt.value.annotation.id, node.name)
                        elif isinstance(stmt.value, ast.Compare) and len(stmt.value.ops) == 1 and isinstance(stmt.value.ops[0], ast.Eq):
                            if isinstance(stmt.value.left, ast.Name) and stmt.value.left.id == node.args.args[0].arg and isinstance(stmt.value.comparators[0], ast.Constant):
                                validate_constant(stmt.value.comparators[0], stmt.value.annotation.id, node.name)
                        # Check for value type validation
                        elif isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "type" and len(stmt.value.args) == 1 and isinstance(stmt.value.args[0], ast.Name):
                            validate_type(stmt.value.args[0].id, stmt.value.annotation.id, node.name)

# Define a function to validate constants
def validate_constant(const, expected_type, function_name):
    # Validate integer constant
    if expected_type == "int":
        if not isinstance(const.value, int):
            print(f"Warning: {function_name} should return an integer")
        elif const.value < -2147483648 or const.value > 2147483647:
            print(f"Warning: {function_name} should return an integer in the range [-2147483648, 2147483647]")
    # Validate float constant
    elif expected_type == "float":
        if not isinstance(const.value, float):
            print(f"Warning: {function_name} should return a float")
        elif const.value < -3.4028235e38 or const.value > 3.4028235e38:
            print(f"Warning: {function_name} should return a float in the range [-3.4028235e38, 3.4028235e38]")
    # Validate string constant
    elif expected_type == "str":
        if not isinstance(const.value, str):
            print(f"Warning: {function_name} should return a string")
    # Validate boolean constant
    elif expected_type == "bool":
        if not isinstance(const.value, bool):
            print(f"Warning: {function_name} should return a boolean")

def validate_type(value_name, expected_type, function_name):
    # Validate integer type
    if expected_type == "int":
        if value_name != "int":
            print(f"Warning: {function_name} should return an integer")
    # Validate float type
    elif expected_type == "float":
        if value_name != "float":
            print(f"Warning: {function_name} should return a float")
    # Validate string type
    elif expected_type == "str":
        if value_name != "str":
            print(f"Warning: {function_name} should return a string")
    # Validate boolean type
    elif expected_type == "bool":
        if value_name != "bool":
            print(f"Warning: {function_name} should return a boolean")
    # Validate list type
    elif expected_type == "list":
        if value_name != "list":
            print(f"Warning: {function_name} should return a list")
    # Validate tuple type
    elif expected_type == "tuple":
        if value_name != "tuple":
            print(f"Warning: {function_name} should return a tuple")
    # Validate dictionary type
    elif expected_type == "dict":
        if value_name != "dict":
            print(f"Warning: {function_name} should return a dictionary")

