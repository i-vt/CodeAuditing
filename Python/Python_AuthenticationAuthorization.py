import ast

UNSAFE_AUTH_FUNCTIONS = ["authenticate", "authorize"]
SECURE_HASH_FUNCTIONS = ["bcrypt", "scrypt", "argon2"]

def is_unsafe_auth_call(call):
    func = call.func
    func_name = func.attr if isinstance(func, ast.Attribute) else func.id
    return func_name in UNSAFE_AUTH_FUNCTIONS

def check_unsalted_password_hashing(node, call):
    arg = call.args[0]
    arg_value = arg.s if isinstance(arg, ast.Str) else None
    if arg_value and not any(hash_func in arg_value for hash_func in SECURE_HASH_FUNCTIONS):
        print(f"Warning: {node.name} uses unsalted password hashing")

def check_insecure_session_management(node, call):
    arg_value = call.args[0].s.lower()
    if "secure" not in arg_value:
        print(f"Warning: {node.name} uses insecure session management")

def check_incomplete_authorization(node, call):
    auth_dict = call.args[1]
    unchecked_keys = [key.s for key in auth_dict.keys if not any(s in key.s.lower() for s in ["allow", "deny"])]
    if unchecked_keys:
        print(f"Warning: {node.name} performs incomplete authorization checks for keys: {unchecked_keys}")

def check_overly_permissive_authorization(node, call):
    auth_dict = call.args[1]
    allow_rules = [rule for rule in auth_dict.values if isinstance(rule, ast.Constant) and rule.value is True and "allow" in rule.parent.keys.s]
    deny_rules = [rule for rule in auth_dict.values if isinstance(rule, ast.Constant) and rule.value is True and "deny" in rule.parent.keys.s]

    if allow_rules and not deny_rules:
        print(f"Warning: {node.name} includes overly permissive 'allow' rules in its authorization checks")
    if deny_rules and not allow_rules:
        print(f"Warning: {node.name} includes overly permissive 'deny' rules in its authorization checks")


def audit_auth_and_authz(node):
    if not isinstance(node, ast.FunctionDef):
        return

    for call in ast.walk(node):
        if isinstance(call, ast.Call) and is_unsafe_auth_call(call):
            if len(call.args) > 0:
                if call.func.id == "authenticate":
                    check_unsalted_password_hashing(node, call)
                elif call.func.id == "authorize":
                    check_insecure_session_management(node, call)
                    if len(call.args) > 1 and isinstance(call.args[1], ast.Dict):
                        check_incomplete_authorization(node, call)
                        check_overly_permissive_authorization(node, call)
                        
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        for node in ast.walk(tree):
            audit_auth_and_authz(node)

# Example usage
#traverse_ast("example.py")
